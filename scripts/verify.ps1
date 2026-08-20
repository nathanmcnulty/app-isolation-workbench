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

    $bundleManifestPath = Join-Path ([IO.Path]::GetTempPath()) "aiw-bundle-$([guid]::NewGuid()).json"
    try {
        $bundleJson = cargo run --quiet --locked -p aiw-cli -- bundle build --root . --spec .\examples\assessment-bundle-spec.json
        if ($LASTEXITCODE -ne 0) { throw 'assessment bundle build failed' }
        $bundleJson | ConvertFrom-Json | Out-Null
        [IO.File]::WriteAllText(
            $bundleManifestPath,
            ($bundleJson -join [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
        cargo run --quiet --locked -p aiw-cli -- bundle verify --root . --manifest $bundleManifestPath | ConvertFrom-Json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'assessment bundle verification failed' }
    }
    finally {
        Remove-Item -LiteralPath $bundleManifestPath -Force -ErrorAction SilentlyContinue
    }

    foreach ($schemaKind in @(
        'assessment-bundle-manifest',
        'assessment-bundle-spec',
        'assessment-bundle-verification',
        'token-evidence',
        'windows-sandbox-plan',
        'mxc-golden-probe-plan'
    )) {
        cargo run --quiet --locked -p aiw-cli -- schema $schemaKind | ConvertFrom-Json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "schema generation failed: $schemaKind" }
    }

    Write-Host 'AIW local verification passed.' -ForegroundColor Green
}
finally {
    Pop-Location
}
