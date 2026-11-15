#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param([switch]$AppContainerControl)
# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'build-storage.ps1')
$buildTarget=(Assert-AiwBuildStoragePolicy -RepositoryRoot $repo).targetDirectory
$previous=$env:CARGO_TARGET_DIR
$previousFlags=$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS
Push-Location -LiteralPath $repo
try {
    $env:CARGO_TARGET_DIR=$buildTarget
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS='-C target-feature=+crt-static'
    & cargo build --locked -p aiw-control-fixture --bin aiw-control-fixture --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Control fixture build failed' }
    $artifact=Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc\debug\aiw-control-fixture.exe'
    [ordered]@{schemaVersion='aiw.dev/control-fixture-build/v0alpha1'; artifact=$artifact; sha256=(Get-FileHash -LiteralPath $artifact).Hash.ToLowerInvariant()} | ConvertTo-Json
    if ($AppContainerControl) {
        $null=Assert-AiwBuildStoragePolicy -RepositoryRoot $repo
        & cargo build --locked -p aiw-control-appcontainer --target x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) { throw 'AppContainer control launcher build failed' }
        $artifact=Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc\debug\aiw-control-appcontainer.exe'
        [ordered]@{schemaVersion='aiw.dev/control-appcontainer-build/v0alpha1'; artifact=$artifact; sha256=(Get-FileHash -LiteralPath $artifact).Hash.ToLowerInvariant()} | ConvertTo-Json
    }
} finally {
    [Environment]::SetEnvironmentVariable('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS',$previousFlags,'Process')
    $env:CARGO_TARGET_DIR=$previous
    Pop-Location
}
