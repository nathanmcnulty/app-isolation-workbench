# Dedicated QEMU VM preflight

Observed October 21, 2026 (America/Anchorage), starting from clean
`9f92cfdae0a5ef56b2e90f280b252387fe8d62a9` on
`codex/new-vm-handoff-20261021`. Checkout: `C:\aiw\app-isolation-workbench`.
This is setup evidence, not a disposable-boundary or lifecycle acceptance receipt.

## Machine and inputs

- Windows 11 Enterprise x64, build 26300; computer `AIW`.
- QEMU Standard PC (Q35 + ICH9, 2009), hypervisor present. SMBIOS UUID:
  `652A575B-A462-418E-95BB-360B28516925`.
- Operator `AIW\labadmin`, SID
  `S-1-5-21-3556347314-2314855617-1438300668-1001`.
  Observed token and Explorer shell share session 1 and authentication LUID;
  both are medium integrity, non-elevated, with Administrators disabled.
  This existing administrator account is not the controller-created trial user.
- Azure IMDS was unreachable. Do not substitute this SMBIOS UUID into the Azure
  identity contract; a reviewed QEMU-specific binding and recovery proof are needed.
- Rust/Cargo 1.99.1, x64 MSVC target, Visual Studio Build Tools 2022 with x64 C++
  tools, Windows SDK libraries 10.0.26100.0, PowerShell 7.6.5 and Windows PowerShell
  5.1.26100.9711 are present. GitHub CLI uses existing authenticated credentials.
- Downloaded archive to `C:\AIW-Resume-20261021\AIW-Migration-20261021.zip`.
  Its size/hash match [RESUME-ON-NEW-VM.md](RESUME-ON-NEW-VM.md). Extraction at
  `C:\AIW-Resume-20261021\assets` matches the committed inventory: 59 hashed
  assets plus `inventory.json`, no missing or extra files.
- Windows Authenticode returned `Valid` for `inputs\application.msix`, with the
  expected Nathan McNulty publisher and Microsoft timestamp signer. Full payload
  association must still be verified on the eventual disposable trial worker.

## Session probe

Each PowerShell version passed two positive and twenty rejection cases, with a
read-only current-session observation. Neither accepted the current session for
an application trial. Local results and failures are preserved at
`C:\AIW-Resume-20261021\new-vm-preflight`.

Windows PowerShell initially rejected script loading under its default policy.
The successful invocation used `-ExecutionPolicy Bypass` for that process only;
no persistent execution policy was changed. It also exposed an empty
`$PSScriptRoot` during default-parameter evaluation. The probe now resolves its
default source directory after parameter binding. Both versions passed using
that default after the correction.

```powershell
$ErrorActionPreference = 'Stop'
Set-Location C:\aiw\app-isolation-workbench
& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\aiw\app-isolation-workbench\scripts\test-msix-interactive-session.ps1 -ObserveCurrent
if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell session probe failed' }
& .\scripts\test-msix-interactive-session.ps1 -ObserveCurrent
```

## Remaining gate

The unchanged native source at `9f92cfd` built successfully with
`research-msix-lifecycle`, `--release --locked --target x86_64-pc-windows-msvc`
and static CRT. Output:
`C:\AIW-Build\msix-new-vm-baseline\x86_64-pc-windows-msvc\release\examples\msix_standard_user_lifecycle.exe`,
SHA-256 `7d22740dab342f0811003105b298762027e4fbd22f26bb38f9ffe9ee2a0099d6`.
Build log: `C:\AIW-Resume-20261021\new-vm-preflight\baseline-release-build.log`.
This binary retains the old Azure pins and has not been executed. It verifies
the build environment only. Governance validation and `git diff --check` passed
for the preflight documentation and session-probe correction.

The user has been asked for QEMU management access or an existing verified
checkpoint and restore procedure. Do not create the timed trial account or run
the application before establishing recovery. Native/controller rebinding must
preserve fixed identity checks, real interactive token/session binding, held
process custody and exact cleanup. Archived controllers remain unchanged.
