[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,
    [string]$LaunchProfile,
    [string]$LaunchProfileSha256
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$productRoot = Join-Path $repoRoot 'crates\aiw-cli\product\notepad-plus-plus'
$cliSource = Join-Path $repoRoot 'target\release\aiw.exe'
$projectSource = Join-Path $productRoot 'project.yaml'
$manifestSource = Join-Path $productRoot 'manifest.json'
$output = [IO.Path]::GetFullPath($OutputDirectory)

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Assert-LowerSha256([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw "$Name must be a lowercase SHA-256" }
}

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

if (Test-Path -LiteralPath $output) { throw "Output directory already exists; choose a new path: $output" }
if (-not (Test-Path -LiteralPath $productRoot -PathType Container)) { throw "Required product asset directory is missing: $productRoot" }
foreach ($path in @($projectSource, $manifestSource)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required product asset is missing: $path" }
}

Push-Location -LiteralPath $repoRoot
try {
    & cargo build --locked --release -p aiw-cli
    if ($LASTEXITCODE -ne 0) { throw 'release aiw-cli build failed' }

    $guestBuildText = & (Join-Path $PSScriptRoot 'build-guest-agent.ps1') -Profile release | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'release guest-agent build failed' }
    $guestBuild = $guestBuildText | ConvertFrom-Json
    $guestSource = [IO.Path]::GetFullPath([string]$guestBuild.artifact)
    if (-not (Test-Path -LiteralPath $guestSource -PathType Leaf)) { throw "guest-agent artifact is missing: $guestSource" }
    if (-not (Test-Path -LiteralPath $cliSource -PathType Leaf)) { throw "release CLI artifact is missing: $cliSource" }

    $manifest = Get-Content -Raw -LiteralPath $manifestSource | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 'aiw.dev/admin-product-assets/v0alpha1' -or $manifest.productId -notlike 'notepad-plus-plus-*') {
        throw 'product manifest is not the supported Notepad++ contract'
    }
    if ($null -ne $LaunchProfile -xor $null -ne $LaunchProfileSha256) { throw 'LaunchProfile and LaunchProfileSha256 must be supplied together' }
    $profileSource = $null
    if ($LaunchProfile) {
        $profileSource = [IO.Path]::GetFullPath($LaunchProfile)
        if (-not (Test-Path -LiteralPath $profileSource -PathType Leaf)) { throw "launch profile is missing: $profileSource" }
        Assert-LowerSha256 $LaunchProfileSha256 'LaunchProfileSha256'
        $profile = Get-Content -Raw -LiteralPath $profileSource | ConvertFrom-Json
        if ($profile.profileSha256 -ne $LaunchProfileSha256) { throw 'launch profile JSON does not match the supplied profile hash' }
        $actualProfileHash = (Get-FileHash -LiteralPath $profileSource -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualProfileHash -ne $LaunchProfileSha256) { throw 'launch profile bytes do not match the supplied profile hash' }
    }

    New-Item -ItemType Directory -Path $output -Force:$false | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $output 'tools') -Force:$false | Out-Null
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $output 'aiw.exe')
    Copy-Item -LiteralPath $guestSource -Destination (Join-Path $output 'tools\aiw-guest-agent.exe')
    Copy-Item -LiteralPath $projectSource -Destination (Join-Path $output 'project.yaml')
    if ($profileSource) { Copy-Item -LiteralPath $profileSource -Destination (Join-Path $output 'launch-profile.json') }

    $manifest.projectPath = 'project.yaml'
    $manifest.guestAgentPath = 'tools/aiw-guest-agent.exe'
    $manifest.projectSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'project.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.guestAgentSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($profileSource) {
        $manifest.launchProfilePath = 'launch-profile.json'
        $manifest.profileSha256 = $LaunchProfileSha256
    } else {
        $manifest.PSObject.Properties.Remove('launchProfilePath')
        $manifest.PSObject.Properties.Remove('profileSha256')
    }
    Write-Utf8NoBom (Join-Path $output 'manifest.json') ($manifest | ConvertTo-Json -Depth 20)

    $payloadFiles = Get-ChildItem -LiteralPath $output -File -Recurse | Where-Object { $_.Name -ne 'receipt.json' } |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($output, $_.FullName).Replace('\', '/')
            [ordered]@{ path = $relative; sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        } | Sort-Object path
    $receiptCore = [ordered]@{
        schemaVersion = 'aiw.dev/preview-package-receipt/v0alpha1'
        productId = [string]$manifest.productId
        files = @($payloadFiles)
        receiptLast = $true
    }
    $receiptHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Get-CanonicalJsonBytes $receiptCore))).ToLowerInvariant()
    $receipt = [ordered]@{ schemaVersion = $receiptCore.schemaVersion; productId = $receiptCore.productId; files = $receiptCore.files; receiptLast = $true; receiptSha256 = $receiptHash }
    Write-Utf8NoBom (Join-Path $output 'receipt.json') ($receipt | ConvertTo-Json -Depth 20)
    Write-Output ($receipt | ConvertTo-Json -Depth 20 -Compress)
}
finally { Pop-Location }
