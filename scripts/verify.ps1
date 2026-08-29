[CmdletBinding()]
param(
    [switch]$GovernanceOnly
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot

try {
    $requiredFiles = @(
        'LICENSE',
        'CONTRIBUTING.md',
        'SECURITY.md',
        'README.md',
        'docs\ARCHITECTURE.md',
        'docs\ROADMAP.md',
        'docs\THREAT-MODEL.md',
        '.github\workflows\ci.yml',
        '.github\pull_request_template.md',
        '.github\ISSUE_TEMPLATE\config.yml'
    )

    foreach ($relativePath in $requiredFiles) {
        $path = Join-Path $repoRoot $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required governance file is missing: $relativePath"
        }
    }

    $licenseText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'LICENSE')
    if ($licenseText -notmatch 'Apache License' -or $licenseText -notmatch 'Version 2\.0') {
        throw 'LICENSE does not contain the Apache License 2.0 text'
    }

    $readmeText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'README.md')
    foreach ($requiredTerm in @('Workbench', 'Studio', 'v0alpha2', 'Windows 11 24H2', 'no automatic telemetry')) {
        if ($readmeText -notmatch [regex]::Escape($requiredTerm)) {
            throw "README.md is missing required product-status term: $requiredTerm"
        }
    }

    $workflowText = Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.github\workflows\ci.yml')
    $workflowUses = [regex]::Matches($workflowText, '(?m)^\s*uses:\s*([^\s#]+)')
    foreach ($match in $workflowUses) {
        if ($match.Groups[1].Value -notmatch '@[0-9a-fA-F]{40}$') {
            throw "GitHub Actions must be pinned to a full commit SHA: $($match.Groups[1].Value)"
        }
    }
    if ($workflowUses.Count -eq 0) {
        throw 'CI workflow does not declare an action'
    }

    if ($GovernanceOnly) {
        Write-Host 'AIW governance-file verification passed.' -ForegroundColor Green
        return
    }

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

    cargo run --quiet --locked -p aiw-cli -- analyst validate --report .\examples\analyst-report.json --evidence-log .\examples\analyst-evidence.jsonl --model-pack .\examples\model-pack.json | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'example analyst report validation failed' }

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

    cargo run --quiet --locked -p aiw-cli -- canary evaluate --plan .\examples\canary-plan.json --observations .\examples\canary-observations.json --evidence-log .\examples\canary-evidence.jsonl | ConvertFrom-Json | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'canary evaluation failed' }

    foreach ($schemaKind in @(
        'assessment-bundle-manifest',
        'assessment-bundle-spec',
        'assessment-bundle-verification',
        'canary-observation-set',
        'canary-plan',
        'canary-report',
        'analyst-report',
        'analyst-report-validation',
        'token-evidence',
        'windows-sandbox-plan',
        'windows-sandbox-cli-lifecycle-plan',
        'windows-sandbox-completion-expectation',
        'windows-sandbox-completion-receipt',
        'windows-sandbox-completion-verification',
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
