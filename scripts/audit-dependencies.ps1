[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot

try {
    cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'locked Cargo metadata validation failed' }

    cargo audit
    if ($LASTEXITCODE -ne 0) { throw 'RustSec dependency audit failed' }

    Write-Host 'AIW dependency audit passed.' -ForegroundColor Green
}
finally {
    Pop-Location
}
