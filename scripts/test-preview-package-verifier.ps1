[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify-preview-package.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "aiw-preview-verifier-$([guid]::NewGuid().ToString('N'))"

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-LowerSha256([byte[]]$Bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-Rejected([scriptblock]$Operation, [string]$Case) {
    try {
        & $Operation | Out-Null
    }
    catch {
        return
    }
    throw "Preview package verifier accepted $Case"
}

try {
    New-Item -ItemType Directory -Path (Join-Path $root 'product') | Out-Null
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixed-cli-bytes'
    Write-Utf8NoBom (Join-Path $root 'product\manifest.json') '{"fixed":true}'
    $records = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            sizeBytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object { $_.path })
    $core = [ordered]@{
        schemaVersion = 'aiw.dev/preview-package-receipt/v0alpha1'
        productId = 'notepad-plus-plus-local-settings'
        files = $records
        receiptLast = $true
    }
    $receiptSha256 = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    $receipt = [ordered]@{
        schemaVersion = $core.schemaVersion
        productId = $core.productId
        files = $core.files
        receiptLast = $true
        receiptSha256 = $receiptSha256
    }
    Write-Utf8NoBom (Join-Path $root 'receipt.json') ($receipt | ConvertTo-Json -Depth 20)

    $verified = & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 | ConvertFrom-Json
    if ($verified.exactInventory -ne $true -or $verified.filesVerified -ne 2) {
        throw 'Preview package verifier did not confirm the valid fixture'
    }

    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'changed-cli-bytes'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 } 'changed payload bytes'
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixed-cli-bytes'

    Write-Utf8NoBom (Join-Path $root 'unexpected.txt') 'unexpected'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 } 'an unexpected file'
    Remove-Item -LiteralPath (Join-Path $root 'unexpected.txt')

    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 ('0' * 64) } 'a wrong independent receipt identity'
    Write-Host 'Preview package verifier contract passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
