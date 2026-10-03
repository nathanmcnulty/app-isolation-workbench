[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$PackageRoot,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string]$ReceiptSha256,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision
)

$ErrorActionPreference = 'Stop'
$root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PackageRoot)
$receiptPath = Join-Path $root 'receipt.json'

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 30 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-LowerSha256([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
}

function Assert-Ordinary([string]$Path, [string]$Label, [switch]$Directory) {
    if (-not (Test-Path -LiteralPath $Path -PathType $(if ($Directory) { 'Container' } else { 'Leaf' }))) { throw "$Label is missing" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label is a reparse point" }
}

Assert-Ordinary $root 'Package root' -Directory
Assert-Ordinary $receiptPath 'Package receipt'
if ((Get-Item -LiteralPath $receiptPath).Length -gt 1048576) { throw 'Package receipt exceeds the bounded contract' }
$rootPrefix = $root.TrimEnd('\') + '\'

$receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
if ($receipt.schemaVersion -cne 'aiw.dev/desktop-package/v0alpha1' -or
    $receipt.receiptLast -ne $true -or
    $receipt.sourceRevision -cne $SourceRevision -or
    $receipt.productIds.Count -ne 2 -or
    @($receipt.productIds) -cnotcontains 'notepad-plus-plus' -or
    @($receipt.productIds) -cnotcontains 'notepad-plus-plus-interactive') {
    throw 'Package receipt does not match the closed desktop package contract'
}

$records = @($receipt.files)
if ($records.Count -eq 0) { throw 'Package receipt has no payload records' }
$recordPaths = @($records | ForEach-Object { [string]$_.path })
if ((ConvertTo-Json $recordPaths -Compress) -cne (ConvertTo-Json (@($recordPaths | Sort-Object)) -Compress)) { throw 'Package receipt paths are not sorted' }
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$safeRecords = foreach ($record in $records) {
    $relative = [string]$record.path
    if ($relative -eq 'receipt.json' -or $relative -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$' -or [IO.Path]::IsPathRooted($relative)) { throw "Package receipt contains an unsafe path: $relative" }
    if (-not $seen.Add($relative)) { throw "Package receipt contains duplicate paths: $relative" }
    if ([string]$record.sha256 -notmatch '^[0-9a-f]{64}$' -or [long]$record.sizeBytes -lt 0) { throw "Package receipt contains an invalid file record: $relative" }
    [ordered]@{ path = $relative; sizeBytes = [long]$record.sizeBytes; sha256 = [string]$record.sha256 }
}

$receiptCore = [ordered]@{
    schemaVersion = [string]$receipt.schemaVersion
    sourceRevision = [string]$receipt.sourceRevision
    productIds = @($receipt.productIds)
    cliSha256 = [string]$receipt.cliSha256
    desktopSha256 = [string]$receipt.desktopSha256
    guestAgentSha256 = [string]$receipt.guestAgentSha256
    files = @($safeRecords)
    receiptLast = $true
}
$calculatedReceiptSha256 = Get-LowerSha256 (Get-CanonicalJsonBytes $receiptCore)
if ($calculatedReceiptSha256 -cne $ReceiptSha256 -or [string]$receipt.receiptSha256 -cne $ReceiptSha256) { throw 'Package receipt identity differs from the independently supplied hash' }
if ([string]$receipt.cliSha256 -notmatch '^[0-9a-f]{64}$' -or [string]$receipt.desktopSha256 -notmatch '^[0-9a-f]{64}$' -or [string]$receipt.guestAgentSha256 -notmatch '^[0-9a-f]{64}$') { throw 'Package executable or guest-agent identities are invalid' }

foreach ($record in $safeRecords) {
    $relative = [string]$record.path
    $segments = $relative.Split('/')
    $parent = $root
    if ($segments.Count -gt 1) {
        foreach ($segment in $segments[0..($segments.Count - 2)]) {
            $parent = Join-Path $parent $segment
            Assert-Ordinary $parent "Package payload parent for $relative" -Directory
        }
    }
    $path = [IO.Path]::GetFullPath((Join-Path $root ($relative.Replace('/', '\'))))
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Package payload escapes the package root: $relative" }
    Assert-Ordinary $path "Package payload $relative"
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Length -ne [long]$record.sizeBytes) { throw "Package payload size differs from receipt: $relative" }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$record.sha256) { throw "Package payload hash differs from receipt: $relative" }
}

$reparse = Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
if ($reparse) { throw 'Package tree contains a reparse point' }
$actualPaths = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.FullName -cne $receiptPath } | ForEach-Object { $_.FullName.Substring($rootPrefix.Length).Replace('\', '/') } | Sort-Object)
if ((ConvertTo-Json $actualPaths -Compress) -cne (ConvertTo-Json $recordPaths -Compress)) { throw 'Package inventory contains missing or unexpected files' }

$required = @('aiw.exe', 'aiw-desktop.exe', 'README.txt', 'LICENSE', 'verify-desktop-package.ps1', 'product/notepad-plus-plus/manifest.json', 'product/notepad-plus-plus/project.yaml', 'product/notepad-plus-plus/tools/aiw-guest-agent.exe', 'product/notepad-plus-plus-interactive/manifest.json', 'product/notepad-plus-plus-interactive/project.yaml', 'product/notepad-plus-plus-interactive/tools/aiw-guest-agent.exe')
foreach ($path in $required) { if (-not $seen.Contains($path)) { throw "Closed package file is missing: $path" } }
if ($seen.Count -ne $required.Count) { throw 'Package receipt contains files outside the closed desktop contract' }

foreach ($exe in @(@{ path = 'aiw.exe'; expected = [string]$receipt.cliSha256 }, @{ path = 'aiw-desktop.exe'; expected = [string]$receipt.desktopSha256 })) {
    $record = $null
    foreach ($candidate in @($safeRecords)) { if ([string]$candidate.path -ceq $exe.path) { $record = $candidate; break } }
    if ($null -eq $record -or [string]$record.sha256 -cne $exe.expected) { throw "Executable identity is not bound by the receipt: $($exe.path)" }
}

foreach ($product in @(
    @{ directory = 'notepad-plus-plus'; id = 'notepad-plus-plus-local-settings'; scenario = 'install-launch-close' },
    @{ directory = 'notepad-plus-plus-interactive'; id = 'notepad-plus-plus-interactive'; scenario = 'install-launch-close' }
)) {
    $productRoot = Join-Path $root "product\$($product.directory)"
    $manifestPath = Join-Path $productRoot 'manifest.json'
    $projectPath = Join-Path $productRoot 'project.yaml'
    $guestPath = Join-Path $productRoot 'tools\aiw-guest-agent.exe'
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.schemaVersion -cne 'aiw.dev/admin-product-assets/v0alpha1' -or $manifest.productId -cne $product.id -or $manifest.projectPath -cne 'project.yaml' -or $manifest.guestAgentPath -cne 'tools/aiw-guest-agent.exe' -or $manifest.scenarioId -cne $product.scenario) { throw "Product manifest does not match its fixed contract: $($product.directory)" }
    if ((Get-FileHash -LiteralPath $projectPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$manifest.projectSha256 -or (Get-FileHash -LiteralPath $guestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$manifest.guestAgentSha256 -or [string]$manifest.guestAgentSha256 -cne [string]$receipt.guestAgentSha256) { throw "Product asset identity differs from its manifest or receipt: $($product.directory)" }
}

[ordered]@{ schemaVersion = 'aiw.dev/desktop-package-verification/v0alpha1'; sourceRevision = $SourceRevision; receiptSha256 = $calculatedReceiptSha256; filesVerified = $records.Count; exactInventory = $true } | ConvertTo-Json -Compress
