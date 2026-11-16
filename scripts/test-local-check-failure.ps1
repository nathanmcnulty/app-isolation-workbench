#Requires -Version 7.6
#Requires -PSEdition Core
# Exercise the unmodified helper in-process; no compiler or provider is invoked.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'build-storage.ps1')
$originalTemp = $env:TEMP
$originalTmp = $env:TMP
$parent = [IO.Path]::GetTempPath()
$owned = Join-Path $parent ('aiwt-' + [guid]::NewGuid().ToString('N').Substring(0,12))
$null = New-Item -ItemType Directory -Path $owned -ErrorAction Stop
function cargo {
    'inert formatter stub; no compiler execution'
    & (Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe') /d /c 'exit /b 101'
}
try {
    $env:TEMP = $owned
    $env:TMP = $owned
    $captured = [Collections.Generic.List[object]]::new()
    $continued = $false
    $threw = $false
    try {
        & (Join-Path $PSScriptRoot 'check-local.ps1') -Check Format | ForEach-Object { $captured.Add($_) }
        $continued = $true
    } catch {
        if ($_.Exception.Message -cne 'AIW local checks failed; inspect the emitted summary and log paths') { throw }
        $threw = $true
    }
    $failure = ($captured -join "`n") | ConvertFrom-Json
    if (-not $threw -or $continued -or $failure.passed -ne $false -or $failure.checks[0].exitCode -ne 101) {
        throw 'A failing local check continued its in-process caller'
    }
    function cargo {
        'inert formatter stub; no compiler execution'
        & (Join-Path ([Environment]::GetFolderPath('System')) 'cmd.exe') /d /c 'exit /b 0'
    }
    $captured.Clear()
    & (Join-Path $PSScriptRoot 'check-local.ps1') -Check Format | ForEach-Object { $captured.Add($_) }
    $success = ($captured -join "`n") | ConvertFrom-Json
    if ($success.passed -ne $true -or $success.checks[0].exitCode -ne 0) {
        throw 'A successful local check did not return normally'
    }
} finally {
    $env:TEMP = $originalTemp
    $env:TMP = $originalTmp
    Remove-AiwOwnedTestDirectory -Path $owned -Parent $parent
}
[ordered]@{passed=$true;cases=2;compilerCalls=0;providerCalls=0;ownedTempRemoved=(-not (Test-Path -LiteralPath $owned))} | ConvertTo-Json -Compress
