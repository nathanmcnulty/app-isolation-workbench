#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ModulePath,

    [Parameter(Mandatory)]
    [string] $CliPath,

    [Parameter(Mandatory)]
    [string] $RootPath
)

# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference = 'Stop'
Import-Module -Name $ModulePath -Force
$manifest = Test-ModuleManifest -Path $ModulePath
if ($manifest.PowerShellVersion -lt [version]'7.6' -or $manifest.CompatiblePSEditions -notcontains 'Core') { throw 'Module does not declare the supported Core baseline' }
$cli = [IO.Path]::GetFullPath($CliPath)
Push-Location -LiteralPath (Split-Path -Parent $cli)
$relativeCli = '.\' + (Split-Path -Leaf $cli)
# ProcessStartInfo.ExitCode belongs to this invocation. A caller's stale native
# state must not replace the structured AIW error or get rewritten by the module.
$global:LASTEXITCODE = 19

try {
    Get-AiwRunStatus -RootPath $RootPath -RunId 'missing-structured-error-test' -CliPath $relativeCli
}
catch {
    $envelope = $_.Exception.Data['AiwError']
    if (-not $envelope) {
        throw 'Invoke-Aiw did not attach the structured error envelope.'
    }
    if ($envelope.code -ne 'AIW_STORAGE_FAILED') {
        throw "Unexpected structured error code: $($envelope.code)"
    }
    if ($_.Exception.Data['ExitCode'] -ne 1) {
        throw "Unexpected AIW exit code: $($_.Exception.Data['ExitCode'])"
    }
    if ($LASTEXITCODE -ne 19) { throw 'Module error handling rewrote unrelated native exit state' }
    return
}
finally { Pop-Location }

throw 'Get-AiwRunStatus unexpectedly succeeded.'
