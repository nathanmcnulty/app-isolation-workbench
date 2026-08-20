[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot

try {
    cargo fmt --all --check
    if ($LASTEXITCODE -ne 0) { throw 'cargo fmt failed' }

    cargo clippy --workspace --all-targets --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'cargo clippy failed' }

    cargo test --workspace --locked
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed' }

    cargo run --quiet --locked -p aiw-cli -- project validate --path .\examples\minimal.aiw.yaml | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'example project validation failed' }

    cargo run --quiet --locked -p aiw-cli -- model-pack validate --path .\examples\model-pack.json | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'example model-pack validation failed' }

    cargo run --quiet --locked -p aiw-cli -- schema project | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'project schema generation failed' }

    cargo run --quiet --locked -p aiw-cli -- probe host | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'host probe failed' }

    cargo run --quiet --locked -p aiw-cli -- probe token | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'token probe failed' }

    cargo run --quiet --locked -p aiw-cli -- provider mxc --plan .\examples\mxc-golden-probe-plan.json | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'MXC plan generation failed' }

    cargo run --quiet --locked -p aiw-cli -- provider mxc-probe --binary C:\AIW\MXC\wxc-exec.exe | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'MXC probe plan generation failed' }

    foreach ($schemaKind in @('token-evidence', 'windows-sandbox-plan', 'mxc-golden-probe-plan')) {
        cargo run --quiet --locked -p aiw-cli -- schema $schemaKind | ConvertFrom-Json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "schema generation failed: $schemaKind" }
    }

    Write-Host 'AIW local verification passed.' -ForegroundColor Green
}
finally {
    Pop-Location
}
