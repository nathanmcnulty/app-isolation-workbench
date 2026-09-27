[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PackageRoot,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ReceiptSha256
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PackageRoot)
$receiptPath = Join-Path $root 'receipt.json'

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-LowerSha256([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Package root does not exist: $root"
}
$rootItem = Get-Item -LiteralPath $root -Force
if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Package root is a reparse point'
}
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw 'Package receipt is missing'
}
$receiptItem = Get-Item -LiteralPath $receiptPath -Force
if (($receiptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Package receipt is a reparse point'
}

$receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
if ($receipt.schemaVersion -ne 'aiw.dev/preview-package-receipt/v0alpha1' -or
    $receipt.productId -notin @('notepad-plus-plus-local-settings', 'bambu-studio-export') -or
    $receipt.receiptLast -ne $true) {
    throw 'Package receipt does not match the supported preview contract'
}

$records = @($receipt.files)
if ($records.Count -eq 0) { throw 'Package receipt has no payload records' }
$recordPaths = @($records | ForEach-Object { [string]$_.path })
$expectedOrder = @($recordPaths | Sort-Object)
if ((ConvertTo-Json $recordPaths -Compress) -cne (ConvertTo-Json $expectedOrder -Compress)) {
    throw 'Package receipt paths are not sorted'
}
$seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$safeRecords = @()
foreach ($record in $records) {
    $relative = [string]$record.path
    if ($relative -eq 'receipt.json' -or
        $relative -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$' -or
        [IO.Path]::IsPathRooted($relative) -or
        @($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "Package receipt contains an unsafe path: $relative"
    }
    if (-not $seenPaths.Add($relative)) { throw 'Package receipt contains duplicate paths' }
    if ([string]$record.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$record.sizeBytes -lt 0) {
        throw "Package receipt contains an invalid file record: $relative"
    }
    $safeRecords += [ordered]@{
        path = $relative
        sizeBytes = [long]$record.sizeBytes
        sha256 = [string]$record.sha256
    }
}

$receiptCore = [ordered]@{
    schemaVersion = [string]$receipt.schemaVersion
    productId = [string]$receipt.productId
    files = $safeRecords
    receiptLast = $true
}
$calculatedReceiptSha256 = Get-LowerSha256 (Get-CanonicalJsonBytes $receiptCore)
if ($calculatedReceiptSha256 -cne $ReceiptSha256 -or
    [string]$receipt.receiptSha256 -cne $ReceiptSha256) {
    throw 'Package receipt identity differs from the independently supplied hash'
}

$rootPrefix = $root.TrimEnd('\') + '\'
foreach ($record in $safeRecords) {
    $relative = [string]$record.path
    $segments = $relative.Split('/')
    $parent = $root
    if ($segments.Count -gt 1) {
        foreach ($segment in $segments[0..($segments.Count - 2)]) {
            $parent = Join-Path $parent $segment
            if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
                throw "Package payload parent is missing: $relative"
            }
            $parentItem = Get-Item -LiteralPath $parent -Force
            if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Package payload parent is a reparse point: $relative"
            }
        }
    }
    $path = [IO.Path]::GetFullPath((Join-Path $root ($relative.Replace('/', '\'))))
    if (-not $path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Package payload is missing or escapes the package root: $relative"
    }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Package payload is a reparse point: $relative"
    }
    if ($item.Length -ne [long]$record.sizeBytes) {
        throw "Package payload size differs from the receipt: $relative"
    }
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne [string]$record.sha256) {
        throw "Package payload hash differs from the receipt: $relative"
    }
}

$reparse = Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
}
if ($reparse) { throw 'Package tree contains a reparse point' }

$actualPaths = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force |
    Where-Object { $_.FullName -ne $receiptPath } |
    ForEach-Object { $_.FullName.Substring($rootPrefix.Length).Replace('\', '/') } |
    Sort-Object)
if ((ConvertTo-Json $actualPaths -Compress) -cne (ConvertTo-Json $recordPaths -Compress)) {
    throw 'Package inventory contains missing or unexpected files'
}

$isBambu = $receipt.productId -eq 'bambu-studio-export'
$productDirectory = if ($isBambu) { 'bambu-studio' } else { 'notepad-plus-plus' }
$projectFile = if ($isBambu) { 'project.json' } else { 'project.yaml' }
$scenarioId = if ($isBambu) { 'local-file-export' } else { 'install-launch-close' }
$productPath = Join-Path $root "product\$productDirectory"
$manifestPath = Join-Path $productPath 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Selected product manifest is missing'
}
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schemaVersion -ne 'aiw.dev/admin-product-assets/v0alpha1' -or
    $manifest.productId -cne $receipt.productId -or
    $manifest.scenarioId -cne $scenarioId -or
    $manifest.projectPath -cne $projectFile -or
    $manifest.guestAgentPath -cne 'tools/aiw-guest-agent.exe' -or
    ($isBambu -and ((@($manifest.PSObject.Properties.Name) -ccontains 'launchProfilePath') -or
                    (@($manifest.PSObject.Properties.Name) -ccontains 'launchProfileSha256')))) {
    throw 'Selected product manifest does not match its fixed contract'
}
$projectPath = Join-Path $productPath $projectFile
$guestPath = Join-Path $productPath 'tools\aiw-guest-agent.exe'
foreach ($asset in @(
    @{ path = $projectPath; expected = [string]$manifest.projectSha256 },
    @{ path = $guestPath; expected = [string]$manifest.guestAgentSha256 }
)) {
    if ($asset.expected -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $asset.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $asset.expected) {
        throw 'Selected product asset identity differs from its manifest'
    }
}

[ordered]@{
    schemaVersion = 'aiw.dev/preview-package-verification/v0alpha1'
    productId = [string]$receipt.productId
    receiptSha256 = $calculatedReceiptSha256
    filesVerified = $records.Count
    exactInventory = $true
} | ConvertTo-Json -Compress
