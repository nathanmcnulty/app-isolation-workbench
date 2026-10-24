#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision,
 [Parameter(Mandatory)][string]$Assembly,
 [Parameter(Mandatory)][string]$Signing,
 [Parameter(Mandatory)][string]$OutputDirectory
)
# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path -Parent $PSScriptRoot
function Assert-Source {
 if((& git -C $repo rev-parse HEAD).Trim() -cne $SourceRevision -or @(& git -C $repo status --porcelain=v1 --untracked-files=all).Count -ne 0){throw 'Exact clean source revision required'}
}
Assert-Source
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $output){throw 'Fresh package destination required'}
foreach($entry in @(@($Assembly,'d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38'),@($Signing,'670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80'))){
 if((Get-FileHash -LiteralPath $entry[0]).Hash.ToLowerInvariant() -cne $entry[1] -or (Get-Item -LiteralPath $entry[0]).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Exact ordinary fixed assembly/signing metadata required'}
}
Push-Location $repo
$flagsName='CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'
$originalFlags=[Environment]::GetEnvironmentVariable($flagsName,'Process')
$originalWorkerSha=[Environment]::GetEnvironmentVariable('AIW_MSIX_WORKER_SHA256','Process')
$originalTarget=[Environment]::GetEnvironmentVariable('CARGO_TARGET_DIR','Process')
try {
 [Environment]::SetEnvironmentVariable($flagsName,(@($originalFlags,'-C target-feature=+crt-static')|Where-Object{$_}) -join ' ','Process')
 [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR',(Join-Path $repo 'target'),'Process')
 & cargo build --locked --release --target x86_64-pc-windows-msvc -p aiw-msix-worker
 if($LASTEXITCODE -ne 0){throw 'Native production MSIX worker build failed'}
 $workerSha=(Get-FileHash -LiteralPath (Join-Path $repo 'target\x86_64-pc-windows-msvc\release\aiw-msix-worker.exe')).Hash.ToLowerInvariant()
 [Environment]::SetEnvironmentVariable('AIW_MSIX_WORKER_SHA256',$workerSha,'Process')
 [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR',(Join-Path $repo 'gui\target'),'Process')
 & cargo +stable build --manifest-path gui/Cargo.toml --locked --release --target x86_64-pc-windows-msvc
 if($LASTEXITCODE -ne 0){throw 'Desktop build failed'}
 Assert-Source
 $null=New-Item -ItemType Directory -Path $output
 $assets=Join-Path $output 'product\msix-worker107';$null=New-Item -ItemType Directory -Path $assets
 Copy-Item -LiteralPath (Join-Path $repo 'target\x86_64-pc-windows-msvc\release\aiw-msix-worker.exe') -Destination (Join-Path $assets 'agent.exe')
 if((Get-FileHash -LiteralPath (Join-Path $assets 'agent.exe')).Hash.ToLowerInvariant() -cne $workerSha){throw 'Copied worker differs from the identity compiled into the desktop'}
 Copy-Item -LiteralPath $Assembly -Destination (Join-Path $assets 'assembly.json')
 Copy-Item -LiteralPath $Signing -Destination (Join-Path $assets 'signing.json')
 foreach($entry in @(@('assembly.json','d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38'),@('signing.json','670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80'))){
  if((Get-FileHash -LiteralPath (Join-Path $assets $entry[0])).Hash.ToLowerInvariant() -cne $entry[1]){throw 'Copied fixed metadata differs; preserve failed package'}
 }
 Copy-Item -LiteralPath (Join-Path $repo 'gui\target\x86_64-pc-windows-msvc\release\aiw-desktop.exe') -Destination (Join-Path $output 'aiw-desktop.exe')
 Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination $output
 $readme="Unsigned development desktop with the fixed VM107 MSIX recipe. Production execution requires stable x64 PowerShell Core 7.6+ at C:\Program Files\PowerShell\7\pwsh.exe on controller and worker, the PowerShell.7.6 HTTPS endpoint and a separately approved clean baseline containing both. Consult docs/handoffs/2026-10-24-powershell76/SETUP-AND-ACCEPTANCE.md before setup or native acceptance. Other Sandbox recipes require their separate product assets. Select the exact signed Notepad++8.9.8 MSIX, review the VM recovery/network/account disclosure, approve the exact plan, then Start separately. Complete the console edit when prompted. The backend collects evidence, cold restores VM107 and verifies clean TLS readback before releasing its durable lease. Broader compatibility and isolation remain unmeasured. If recovery needs attention, select the original workspace/run in retained MSIX reports and use Recover VM107 retained lease. This never repeats application execution. Source: $SourceRevision."
 [IO.File]::WriteAllText((Join-Path $output 'README.txt'),$readme,[Text.UTF8Encoding]::new($false))
 $files=@(Get-ChildItem -LiteralPath $output -File -Recurse|ForEach-Object{@{path=[IO.Path]::GetRelativePath($output,$_.FullName).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}}|Sort-Object path)
 $receipt=@{schemaVersion='aiw.dev/msix-desktop-package/v0alpha1';sourceRevision=$SourceRevision;workerSha256=$workerSha;files=$files;receiptLast=$true;unsigned=$true}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 8))
 $file=[IO.File]::Open((Join-Path $output 'receipt.json'),[IO.FileMode]::CreateNew);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 Assert-Source
 @{packageRoot=$output;sourceRevision=$SourceRevision;receiptSha256=(Get-FileHash -LiteralPath (Join-Path $output 'receipt.json')).Hash.ToLowerInvariant();files=$files.Count;unsigned=$true}|ConvertTo-Json -Compress
}finally{[Environment]::SetEnvironmentVariable($flagsName,$originalFlags,'Process');[Environment]::SetEnvironmentVariable('AIW_MSIX_WORKER_SHA256',$originalWorkerSha,'Process');[Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR',$originalTarget,'Process');Pop-Location}
