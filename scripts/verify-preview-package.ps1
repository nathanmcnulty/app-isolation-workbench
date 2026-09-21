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
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Package root does not exist: $root"
}
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    throw 'Package receipt is missing'
}

$receipt = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
if ($receipt.schemaVersion -ne 'aiw.dev/preview-package-receipt/v0alpha1' -or
    $receipt.productId -ne 'notepad-plus-plus-local-settings' -or
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
if (@($recordPaths | Select-Object -Unique).Count -ne $recordPaths.Count) {
    throw 'Package receipt contains duplicate paths'
}

$rootPrefix = $root.TrimEnd('\') + '\'
foreach ($record in $records) {
    $relative = [string]$record.path
    if ($relative -eq 'receipt.json' -or $relative -match '\\' -or
        [IO.Path]::IsPathRooted($relative) -or
        @($relative.Split('/') | Where-Object { $_ -in @('', '.', '..') }).Count -ne 0) {
        throw "Package receipt contains an unsafe path: $relative"
    }
    if ([string]$record.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$record.sizeBytes -lt 0) {
        throw "Package receipt contains an invalid file record: $relative"
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
    ForEach-Object { [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/') } |
    Sort-Object)
if ((ConvertTo-Json $actualPaths -Compress) -cne (ConvertTo-Json $recordPaths -Compress)) {
    throw 'Package inventory contains missing or unexpected files'
}

$receiptCore = [ordered]@{
    schemaVersion = [string]$receipt.schemaVersion
    productId = [string]$receipt.productId
    files = @($records | ForEach-Object {
        [ordered]@{
            path = [string]$_.path
            sizeBytes = [long]$_.sizeBytes
            sha256 = [string]$_.sha256
        }
    })
    receiptLast = $true
}
$calculatedReceiptSha256 = Get-LowerSha256 (Get-CanonicalJsonBytes $receiptCore)
if ($calculatedReceiptSha256 -cne $ReceiptSha256 -or
    [string]$receipt.receiptSha256 -cne $ReceiptSha256) {
    throw 'Package receipt identity differs from the independently supplied hash'
}

[ordered]@{
    schemaVersion = 'aiw.dev/preview-package-verification/v0alpha1'
    productId = [string]$receipt.productId
    receiptSha256 = $calculatedReceiptSha256
    filesVerified = $records.Count
    exactInventory = $true
} | ConvertTo-Json -Compress
