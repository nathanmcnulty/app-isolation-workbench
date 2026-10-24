#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $MxcSourcePath
)

# AIW runtime contract: stable PowerShell Core >=7.6; no compatibility session.
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') { throw 'AIW requires stable x64 PowerShell Core 7.6 or later' }
foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
$PSModuleAutoLoadingPreference = 'None'
if (@(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
$PSNativeCommandUseErrorActionPreference = $false
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$resolvedMxc = (Resolve-Path -LiteralPath $MxcSourcePath -ErrorAction Stop).Path
$pin = Get-Content -LiteralPath (Join-Path $repoRoot 'third-party\mxc-pin.json') -Raw | ConvertFrom-Json
$actualCommit = (git -C $resolvedMxc rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not read the MXC source revision.' }
if ($actualCommit -cne $pin.commit) {
    throw "MXC source is at $actualCommit; AIW requires $($pin.commit)."
}

$schemaPath = Join-Path $resolvedMxc $pin.developmentSchema
if (-not (Test-Path -LiteralPath $schemaPath -PathType Leaf)) {
    throw "Pinned MXC schema was not found: $schemaPath"
}

$examples = @(
    'examples\mxc-golden-probe-plan.json',
    'examples\mxc-windows-sandbox-probe-plan.json'
)

Push-Location -LiteralPath $repoRoot
try {
    foreach ($example in $examples) {
        $rendered = cargo run --quiet --locked -p aiw-cli -- provider mxc --plan $example | ConvertFrom-Json -Depth 100
        if ($LASTEXITCODE -ne 0) { throw "AIW could not render $example." }
        if ($rendered.pin.commit -cne $pin.commit) {
            throw "Rendered plan pin does not match third-party/mxc-pin.json for $example."
        }

        $configBytes = [Convert]::FromBase64String($rendered.configBase64)
        $configJson = [Text.Encoding]::UTF8.GetString($configBytes)
        if (-not ($configJson | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
            throw "Rendered MXC config does not satisfy the pinned schema: $example"
        }

        $actualHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($configBytes)).ToLowerInvariant()
        if ($actualHash -cne $rendered.configSha256) {
            throw "Rendered MXC config hash does not match its base64 payload: $example"
        }
    }

    Write-Output "AIW MXC plans match pinned revision $($pin.commit)."
}
finally {
    Pop-Location
}
