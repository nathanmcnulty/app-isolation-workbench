#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'verify-repository-content.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('aiw-content-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
$cases = 0
try {
    & git -C $root init --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Cannot initialize inert test repository' }
    [IO.File]::WriteAllText((Join-Path $root 'fixture.json'), '{"synthetic":true}')
    & $guard -RepositoryRoot $root | ConvertFrom-Json | Out-Null
    $cases++
    foreach ($case in @(
        @{name='application.exe';bytes=[byte[]]@(0)},
        @{name='application.msix';bytes=[byte[]]@(0)},
        @{name='evidence.zip';bytes=[byte[]]@(0)},
        @{name='renamed-pe.dat';bytes=[byte[]]@(0x4d,0x5a,0,0)},
        @{name='renamed-zip.dat';bytes=[byte[]]@(0x50,0x4b,3,4)},
        @{name='renamed-msi.dat';bytes=[byte[]]@(0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1)}
    )) {
        $path = Join-Path $root $case.name
        [IO.File]::WriteAllBytes($path, $case.bytes)
        $rejected = $false
        try { & $guard -RepositoryRoot $root | Out-Null } catch {
            if ($_.Exception.Message -notlike '*Opaque application/package content*') { throw }
            $rejected = $true
        }
        if (-not $rejected) { throw "Content guard accepted $($case.name)" }
        Remove-Item -LiteralPath $path
        $cases++
    }
    # Ignore patterns cannot exempt files already added to Git.
    [IO.File]::WriteAllText((Join-Path $root '.gitignore'), '*.zip')
    $ignored = Join-Path $root 'tracked.zip'
    [IO.File]::WriteAllBytes($ignored, [byte[]]@(0))
    & git -C $root add --force -- tracked.zip
    if ($LASTEXITCODE -ne 0) { throw 'Cannot stage inert tracked-payload case' }
    $rejected = $false
    try { & $guard -RepositoryRoot $root | Out-Null } catch {
        if ($_.Exception.Message -notlike '*Opaque application/package content*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Ignore rule bypassed tracked payload guard' }
    $cases++
    Remove-Item -LiteralPath $ignored
    & $guard -RepositoryRoot $root | ConvertFrom-Json | Out-Null
    $cases++
    [ordered]@{passed=$true;cases=$cases;applicationExecuted=$false} | ConvertTo-Json -Compress
} finally {
    # Delete only this script's fresh inert directory, never user inputs.
    if ([IO.Path]::GetFileName($root) -notmatch '^aiw-content-test-[0-9a-f]{32}$') { throw 'Unexpected test directory' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
