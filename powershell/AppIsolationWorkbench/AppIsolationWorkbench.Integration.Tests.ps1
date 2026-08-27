[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ModulePath,

    [Parameter(Mandatory)]
    [string] $CliPath,

    [Parameter(Mandatory)]
    [string] $RootPath
)

$ErrorActionPreference = 'Stop'
Import-Module -Name $ModulePath -Force

try {
    Get-AiwRunStatus -RootPath $RootPath -RunId 'missing-structured-error-test' -CliPath $CliPath
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
    return
}

throw 'Get-AiwRunStatus unexpectedly succeeded.'
