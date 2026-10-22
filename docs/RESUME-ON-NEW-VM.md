# Resume on the dedicated VM

Prepared 2026-10-21 from code head `5688db4eb681fdc9a7e3987bb091b89de941d1bd`.
Branch `codex/new-vm-handoff-20261021` contains that entire development history
plus this handoff. This is a migration checkpoint, not MSIX lifecycle acceptance.

## Checkout and assets

In PowerShell 7 on the new VM, with Git and GitHub CLI available/authenticated:

```powershell
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath C:\src\app-isolation-workbench) { throw 'Inspect the existing checkout; do not clone over it' }
New-Item -ItemType Directory -Path C:\src -Force | Out-Null
git clone --branch codex/new-vm-handoff-20261021 https://github.com/nathanmcnulty/app-isolation-workbench.git C:\src\app-isolation-workbench
if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
Set-Location C:\src\app-isolation-workbench
.\scripts\work-status.ps1
```

Preserve unrelated changes in any existing checkout before switching branches.
Start Codex in that folder with [RESUME-PROMPT.md](RESUME-PROMPT.md).

The **draft** release `migration-handoff-20261021` preserves research assets
before Actions run `37711841372`'s artifacts expire on October 22. Leave it draft.
Authenticated maintainers can download it. These commands verify and extract data
only; they do not run an archived script or executable:

```powershell
$ErrorActionPreference = 'Stop'
$destination = 'C:\AIW-Resume-20261021'
if (Test-Path -LiteralPath $destination) { throw 'Preserve the previous extraction; choose a fresh destination' }
New-Item -ItemType Directory -Path $destination | Out-Null
gh release download migration-handoff-20261021 --repo nathanmcnulty/app-isolation-workbench --pattern AIW-Migration-20261021.zip --dir $destination
if ($LASTEXITCODE -ne 0) { throw 'Download failed; use normal browser authentication if required' }
$archive = Join-Path $destination 'AIW-Migration-20261021.zip'
if ((Get-Item -LiteralPath $archive).Length -ne 9133397 -or
    (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'fb7b8ba88e091562bd50bab514d4b6de2181f4fa5623a8e5e6eba8750b6911e7') {
    throw 'Archive identity differs; do not extract or execute it'
}
$assets = Join-Path $destination 'assets'
[IO.Compression.ZipFile]::ExtractToDirectory($archive, $assets)
$manifest = Get-Content -LiteralPath (Join-Path $assets 'inventory.json') -Raw | ConvertFrom-Json
$committedInventory = Join-Path $PWD 'docs\handoff\20261021\inventory.json'
$archivedInventory = [IO.File]::ReadAllText((Join-Path $assets 'inventory.json')).Replace("`r`n", "`n")
$repositoryInventory = [IO.File]::ReadAllText($committedInventory).Replace("`r`n", "`n")
if ($archivedInventory -cne $repositoryInventory) { throw 'Inventory differs from committed handoff' }
$expected = @('inventory.json') + @($manifest.files.path)
$actual = @(Get-ChildItem -LiteralPath $assets -Recurse -Force -File | ForEach-Object {
    [IO.Path]::GetRelativePath($assets, $_.FullName).Replace('\','/')
})
if (@(Compare-Object $expected $actual -CaseSensitive).Count -ne 0) { throw 'Archive file inventory differs' }
foreach ($file in $manifest.files) {
    $path = Join-Path $assets $file.path
    if ((Get-Item -LiteralPath $path).Length -ne $file.sizeBytes -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) {
        throw "Retained asset differs: $($file.path)"
    }
}
[pscustomobject]@{ assets = $assets; filesVerified = $manifest.files.Count; exactInventory = $true }
```

Successful PowerShell scripts use terminating errors; do not check an unrelated
`$LASTEXITCODE` after them. Check it after native programs (`git`, `gh`, `cargo`).

The ZIP has 60 files including its inventory. The committed
[inventory](handoff/20261021/inventory.json) records every size/hash:

| Asset | Identity and purpose |
| --- | --- |
| `inputs/application.msix` | 8,641,353 bytes; SHA-256 `2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437`; signed Notepad++ 8.9.8 research package |
| `inputs/assembly.json` | 80,279 bytes; SHA-256 `d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38`; hosted payload inventory |
| `inputs/signing.json` | 317 bytes; SHA-256 `670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80`; signing association |
| `inputs/msix_standard_user_lifecycle.exe` | 905,728 bytes; SHA-256 `b6ba89f8890383ad430fd7efe6ba68887c04ea52aceeb8c01f20f41aa6c6a01c`; historical research control from `c2fda15d2e2aa3b6ea2a4ad774245b80c895fa37`, pinned to OLD worker |
| `reference/old-vm/` | 15 exact historical controller/account/staging/preparation source files; preserved bytes retain embedded hash checks |
| `evidence/` | 39 selected Scheduler/readback, r5 WTS failure, r6 baseline/auth/expiry, package-install failure/cleanup and validation records |

Hosted assembly/signing source: `bcf6f8243334c4478f06ee825b8ef20867c9da38`;
[successful run](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/37711841372).
Reverify publisher signature/timestamp and payload association on the new worker
before installation. The native executable is an unsigned research build, not a
product release. Its old VM pins make it **reference material**; retain the signed
MSIX unchanged while rebuilding the rebound driver.

Excluded: private keys, credentials, `private-primary-login/`, RDP files,
credential-store backups, Azure poller continuation tokens, auth caches, build
caches and obsolete generators. Old local evidence/disks were not deleted. This
is a resume bundle, not a forensic copy of every historical run. Historical TEMP
paths are provenance, not dependencies. Licenses remain inside the MSIX; the
archive README links the original Notepad++ source/distribution.

## Exact stopping point

The administrator/Sandbox packaging milestone is complete: Bambu Studio and both
Notepad++ recipes passed signed public-entry acceptance and interactive
edit/save/export. See [BAMBU-PUBLIC-ACCEPTANCE.md](BAMBU-PUBLIC-ACCEPTANCE.md).

The next milestone is [NOTEPAD-MSIX-LIFECYCLE.md](NOTEPAD-MSIX-LIFECYCLE.md).
Signed installation and all 220 installed payload entries passed historically;
**normal non-elevated packaged execution, document edit/save, configuration,
post-workflow payload verification and exact normal uninstall remain open**.
An elevated operator's activation did not satisfy that contract.

The r5 direct Azure SYSTEM `vm-launch-control` failed `CreateProcessAsUserW`
with `0x80070005` before child creation or installation, with an inherited parent
job observed. This is setup failure, not application incompatibility. The job
explanation remains a hypothesis.

A default SYSTEM Scheduler observation then measured required privileges and
immediate job flag `0x1000`. Its fixed cmd control passed: no inherited child job,
suspended assignment into the exact owned kill-on-close job, exit 42, empty
streams/job and independently verified task/process cleanup. This proves only
that control, not WTS or the application lifecycle.

Latest reviewed WTS Scheduler templates, preserved verbatim:

| File | SHA-256 |
| --- | --- |
| `scheduler-primary-worker-r6.ps1` | `ea1508ef30612e38c8152e8599f5474e110af396a37ce305b70408c1841b8878` |
| `scheduler-primary-controller-r6.ps1` | `80405853464eb9fc6d0d576f6978ff2e3cb70eb31938d86f7e36ebba8d7756c9` |
| `managed-scheduler-primary-r6.py` | `e515aeffbff211c453232c3d603c3122d42f1a2c1d5a330f453c1deb1c27fe62` |

Review fixed orphan-driver cleanup: the outer controller holds/verifies the exact
native process and independently checks its exit. These templates were reviewed
and parsed, **never submitted live**. r6 reached a clean baseline and account
creation, but no real standard-user Explorer shell. Protected RDP input failed;
the 30-minute preparation window expired October 11. Neither preparation nor
native WTS control was dispatched. Credentials were cleared and the client closed.
The old subscription subsequently ran out of funds, per the user. No old live
trial, account window or approval can be adopted here.

## Next bounded task

1. Run work-status; read this document, the lifecycle design and execution plan.
   Inspect the **new** machine read-only: OS/build, architecture, current
   token/SID/elevation, interactive session/shell, tools and Azure IMDS identity
   if applicable. Establish a disposable worker/checkpoint before app execution.
   A development checkout is not itself a clean-worker proof. Do not contact,
   recover, clean up or provision in the exhausted old subscription.
2. Make one narrow reviewed research rebind. Native source
   `crates/aiw-windows-platform/src/research_msix_lifecycle.rs` pins `VM_ID`,
   `VM_OPERATOR_SID`, standard-user SID prefix, computer name, and IMDS VM name/
   subscription. Archived controllers also pin region, disk, snapshot/baseline
   marker, host source path, SIDs, paths, hashes and record names. Derive new values
   from actual observations and update all consumers consistently. Preserve checks;
   do not create a generic command interface. Review identity and cleanup before
   mutation. Keep the historical archive unchanged.
3. Rebuild the rebound native driver and update preparation/template hashes.
   Required feature: `research-msix-lifecycle` (the separate `research-msix-control`
   builds a different example). With Rust >=1.88, x64 MSVC target, MSVC C++ build
   tools/Windows SDK and PowerShell 7, the build shape from the checkout root is:

   ```powershell
   $ErrorActionPreference = 'Stop'
   $env:CARGO_TARGET_DIR = 'C:\AIW-Build\msix-new-vm'
   $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS = '-C target-feature=+crt-static'
   cargo build -p aiw-windows-platform --example msix_standard_user_lifecycle --features research-msix-lifecycle --target x86_64-pc-windows-msvc --release --locked
   if ($LASTEXITCODE -ne 0) { throw 'Research driver build failed' }
   Get-FileHash -LiteralPath C:\AIW-Build\msix-new-vm\x86_64-pc-windows-msvc\release\examples\msix_standard_user_lifecycle.exe -Algorithm SHA256
   ```

   Record new source and byte identities; never substitute a new hash into old
   receipts. One build owner per target directory.
4. Prove the fixed Scheduler control on the new disposable boundary. Prepare
   inputs **before** starting a new 30-minute account window. Establish real
   standard-user interactive login and matching shell/token. Use the canonical
   64-character nonce and `scripts/research/msix-primary-preparation.ps1` contract.
   A matching session ID/profile is insufficient. Codex now has local VM access;
   avoid recreating the old remote clipboard/protected prompt loop. If human login
   is needed, arrange it before creating the short-lived window.
5. Run fixed native `vm-launch-control` through the reviewed SYSTEM Scheduler
   route. Require actual user token/session binding, exit 42, empty owned job and
   exact native/task cleanup. Missing process custody is fatal: retain failure,
   then restore the boundary rather than retry/adopt a failed window.
6. Only after that passes, run the complete signed Notepad++ lifecycle in a
   fresh disposable trial, with every gate in the lifecycle design. Preserve
   medium-IL/non-elevated/package identity and payload gates. Feed measured lessons
   into existing typed assessment services. Separate driver/setup failure from
   app incompatibility and function success from effective isolation.
7. Independently review consequential changes. Use proportional negative tests,
   preparation tests, native lifecycle tests, PowerShell 5.1 requirements and the
   release example build. Existing logs prove their recorded revisions only.
   Use required hosted CI at integration, then PR/merge and verify main. Commit/
   push stable intermediate work. Do not rerun signing or every historical trial.

## Direction and authority

Finish this delivery slice, then the real-application classic AppContainer
baseline/candidate comparison; evaluate MXC ProcessContainer after its own exact
revision review and disposable controls. See
[MXC-TRAJECTORY-REVIEW-2026-10-07.md](MXC-TRAJECTORY-REVIEW-2026-10-07.md).
VS Code is already planned in [ROADMAP.md](ROADMAP.md). Keep administrator output
simple by default with detailed evidence available. Follow [EXECUTION-PLAN.md](EXECUTION-PLAN.md)
for cost-conscious model/review guidance; avoid expensive models for log polling.

The user authorized continued project development, terminal/computer use and
testing on the dedicated VM, and stable commit/push/PR/merge milestones. Preserve
unrelated work and disposable boundaries. Never use device-code authentication;
use cached broker credentials or the normal browser flow. Do not copy personal
auth state. Signing remains the existing pinned CI flow using personal Artifact
Signing account
`/subscriptions/a80941e8-c2b9-4bc9-83ad-117cc40d0bea/resourceGroups/mvp-automation/providers/Microsoft.CodeSigning/codeSigningAccounts/asa-nathanmcnulty`.
No private signing key needs transfer. This handoff does not publish a public
release, broaden isolation claims or authorize destructive old-infrastructure cleanup.
The user explicitly accepts redoing setup and affected controls on the new VM;
preserved history is context, not a requirement to reconstruct the old environment.
