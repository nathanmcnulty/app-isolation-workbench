#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param([switch]$IncludeWorktrees)

# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
function Read-Git([string[]]$GitArguments) {
    $lines = @(& git --no-optional-locks -C $repoRoot @GitArguments)
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArguments[0]) failed" }
    $lines
}
$head = Read-Git @('rev-parse', 'HEAD')
$branch = Read-Git @('branch', '--show-current')
$status = @(Read-Git @('status', '--short'))
$upstream = & git -C $repoRoot rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>$null
if ($LASTEXITCODE -ne 0) { $upstream = $null }
$difference = $null
if ($upstream) { $difference = Read-Git @('rev-list', '--left-right', '--count', 'HEAD...@{upstream}') }
$result = [ordered]@{
    root = $repoRoot
    branch = $branch
    head = $head
    clean = $status.Count -eq 0
    changedEntries = $status.Count
    status = @($status | Select-Object -First 30)
    statusTruncated = $status.Count -gt 30
    locallyKnownUpstream = $upstream
    aheadBehind = $difference
    upstreamFreshness = 'local refs only; no fetch or network access'
    handoff = Join-Path $repoRoot 'docs/WORKING-STATE.md'
}
if ($IncludeWorktrees) { $result.worktrees = @(Read-Git @('worktree', 'list')) }
$result | ConvertTo-Json -Depth 4
