# Working state

Updated 2026-10-24. Owning branch `codex/new-vm-handoff-20261021`, checkout
`C:\aiw\app-isolation-workbench` on VM203. Start with `scripts/work-status.ps1`.
PR #103 remains open and unmerged. This file is a pointer, not execution authority.

## Current adopted slice

The JSON-order guard correction requested from Dot's review at `96b5a12` is
implemented on this owning PR checkout, based on `e7ac987`. Read
`docs/handoffs/2026-10-24-powershell76/JSON-IDENTITY-GUARD-CORRECTION.md` for
both embedded guards, exact-consumer regressions and independent source review.
Stages A–D and merge remain blocked; no VM or runtime/security change is included.

Nathan adopted `docs/handoffs/2026-10-24-powershell76/GOAL.md` for the complete
offline PowerShell migration, validation and one sanitized source checkpoint push.
Read its VALIDATION.md and SETUP-AND-ACCEPTANCE.md for coverage and the single
bundled provisioning/native-acceptance boundary. Source migration uses stable
x64 Core >=7.6, a fixed machine executable, explicit PowerShell.7.6 HTTPS endpoint,
held runtime identities and bound preparation/request/SYSTEM/user receipts.
Legacy evidence remains readable. Incompatible outstanding preparations fail
before fresh runtime/helper execution; approved tools are never rewritten.

Existing bundled Core 7.6.5 / Windows 10.0.26300.9711 is used only for inert offline tests.
Recommended/CI pinned patch 7.6.7. No machine runtime installation, endpoint,
WinRM/firewall/security change, VM107 provisioning/new baseline or native application trial
is authorized by adoption. The historical provider pins remain deployed; new
execution refuses that old baseline. Native acceptance is pending bundled approval.
Historical research execution and the unbootstrapped offline PowerShell Sandbox
control are explicitly retired; native Rust Sandbox profiles remain separate.

## Historical completed acceptance (do not replay)

Full app run `msix-1792704525359564000`: execution34369c9, reader2dab30b;
Control 42, install/open/edit-save-close/uninstall, 53 document bytes, 220 unchanged
payloads, 6 configs, 44 inventoried files. Cold-clean/released 2026-10-22T21:52:19Z.
Bounded run `msix-bounded-1792816990610240800`: corrected runtime 1879c77,
final harness abd17ea; originals survived missing/partial copies, export failure
retained dirty lease, older inputs unchanged, delayed readiness preceded one
Control 42. No application Run. Cold-clean/released 2026-10-24T05:12:46Z.
Both used the former runtime; neither proves migrated Core native acceptance.
Their leases are released; never recover/replay these completed nonces.
See docs/MSIX-EXECUTION.md for exact receipts and retained evidence locations.

## Worker/recovery boundary

Only VM107: UUID e5cecc90-35c2-4831-bf9c-424be23f7d4e,
MAC CC:34:21:B8:5A:31, IP 192.168.1.174. Never touch VM106/passkeys-worker or restore VM203.
Historical snapshot `aiw-msix-worker107-tls-clean-r1` covers OS/EFI/TPM/no RAM.
The runtime-equipped `aiw-msix-worker107-pwsh76-clean-r1` is planned, not created;
its actual config/provider/runtime pins require approved provisioning/observation.
Normal HTTPS certificate BC14DCC4E37F83161EBB55AF8624E36A79E19256 remains required;
no TLS bypass, default legacy endpoint fallback, credential/key reconfiguration,
foreign lease adoption or automatic dispatch retry. Keep migration release draft.
