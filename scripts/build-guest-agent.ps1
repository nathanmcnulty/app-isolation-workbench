[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $repoRoot 'target\guest-agent-static'
$previousTarget = $env:CARGO_TARGET_DIR

Push-Location -LiteralPath $repoRoot
try {
    $env:CARGO_TARGET_DIR = $targetRoot
    $arguments = @('rustc', '--locked', '-p', 'aiw-guest-agent')
    if ($Profile -eq 'release') {
        $arguments += @('--profile', 'release')
    }
    $arguments += @('--', '-C', 'target-feature=+crt-static')
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'statically linked guest-agent build failed'
    }

    $artifact = Join-Path $targetRoot "$Profile\aiw-guest-agent.exe"
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "guest-agent artifact was not produced: $artifact"
    }
    [ordered]@{
        schemaVersion = 'aiw.dev/guest-agent-build/v0alpha1'
        profile = $Profile
        artifact = $artifact
        sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        crt = 'static'
    } | ConvertTo-Json
}
finally {
    if ($null -eq $previousTarget) {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_TARGET_DIR = $previousTarget
    }
    Pop-Location
}
