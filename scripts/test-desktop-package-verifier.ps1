[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify-desktop-package.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "aiw-desktop-verifier-$([guid]::NewGuid().ToString('N'))"
$sourceRevision = '0123456789abcdef0123456789abcdef01234567'
$hadInheritedLastExitCode = Test-Path -LiteralPath Variable:LASTEXITCODE
$inheritedLastExitCode = if ($hadInheritedLastExitCode) { $global:LASTEXITCODE } else { $null }

function Write-Utf8NoBom([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false)) }
function Get-CanonicalJsonBytes([object]$Value) { return ,([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress))) }
function Get-LowerSha256([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
function Assert-Rejected([scriptblock]$Operation, [string]$Case) { try { & $Operation | Out-Null } catch { return }; throw "Desktop package verifier accepted $Case" }

try {
    $paths = @(
        'aiw.exe', 'aiw-desktop.exe', 'README.txt', 'LICENSE', 'verify-desktop-package.ps1',
        'product/notepad-plus-plus/manifest.json', 'product/notepad-plus-plus/project.yaml', 'product/notepad-plus-plus/tools/aiw-guest-agent.exe',
        'product/notepad-plus-plus-interactive/manifest.json', 'product/notepad-plus-plus-interactive/project.yaml', 'product/notepad-plus-plus-interactive/tools/aiw-guest-agent.exe'
    )
    foreach ($path in $paths) { New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $root $path)) -Force | Out-Null; Write-Utf8NoBom (Join-Path $root $path) "fixture:$path" }
    $guestBytes = [Text.UTF8Encoding]::new($false).GetBytes('fixture:shared-guest')
    foreach ($guestPath in @('product\notepad-plus-plus\tools\aiw-guest-agent.exe', 'product\notepad-plus-plus-interactive\tools\aiw-guest-agent.exe')) { [IO.File]::WriteAllBytes((Join-Path $root $guestPath), $guestBytes) }
    foreach ($product in @(@{ dir = 'notepad-plus-plus'; id = 'notepad-plus-plus-local-settings' }, @{ dir = 'notepad-plus-plus-interactive'; id = 'notepad-plus-plus-interactive' })) {
        $productRoot = Join-Path $root "product\$($product.dir)"
        $project = Join-Path $productRoot 'project.yaml'; $guest = Join-Path $productRoot 'tools\aiw-guest-agent.exe'
        $manifest = [ordered]@{ schemaVersion = 'aiw.dev/admin-product-assets/v0alpha1'; productId = $product.id; projectPath = 'project.yaml'; projectSha256 = (Get-FileHash -LiteralPath $project -Algorithm SHA256).Hash.ToLowerInvariant(); guestAgentPath = 'tools/aiw-guest-agent.exe'; scenarioId = 'install-launch-close'; guestAgentSha256 = (Get-FileHash -LiteralPath $guest -Algorithm SHA256).Hash.ToLowerInvariant() }
        Write-Utf8NoBom (Join-Path $productRoot 'manifest.json') ($manifest | ConvertTo-Json -Depth 10)
    }
    $records = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object { [ordered]@{ path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } } | Sort-Object { $_.path })
    $cliHash = (Get-FileHash -LiteralPath (Join-Path $root 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $desktopHash = (Get-FileHash -LiteralPath (Join-Path $root 'aiw-desktop.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $guestHash = (Get-FileHash -LiteralPath (Join-Path $root 'product\notepad-plus-plus\tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $core = [ordered]@{ schemaVersion = 'aiw.dev/desktop-package/v0alpha1'; sourceRevision = $sourceRevision; productIds = @('notepad-plus-plus', 'notepad-plus-plus-interactive'); cliSha256 = $cliHash; desktopSha256 = $desktopHash; guestAgentSha256 = $guestHash; files = $records; receiptLast = $true }
    $receiptHash = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    Write-Utf8NoBom (Join-Path $root 'receipt.json') (([ordered]@{ schemaVersion = $core.schemaVersion; sourceRevision = $core.sourceRevision; productIds = $core.productIds; cliSha256 = $core.cliSha256; desktopSha256 = $core.desktopSha256; guestAgentSha256 = $core.guestAgentSha256; files = $core.files; receiptLast = $true; receiptSha256 = $receiptHash }) | ConvertTo-Json -Depth 30)

    $valid = & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision | ConvertFrom-Json
    if ($valid.exactInventory -ne $true -or $valid.filesVerified -ne $records.Count) { throw 'Valid desktop package fixture did not verify' }
    & $env:ComSpec /d /c 'exit 19' | Out-Null
    $stale = & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision | ConvertFrom-Json
    if ($stale.exactInventory -ne $true) { throw 'Verifier output depended on stale native exit state' }

    $originalReceipt = [IO.File]::ReadAllBytes((Join-Path $root 'receipt.json'))
    $divergentCore = [ordered]@{ schemaVersion = $core.schemaVersion; sourceRevision = $core.sourceRevision; productIds = $core.productIds; cliSha256 = $core.cliSha256; desktopSha256 = $core.desktopSha256; guestAgentSha256 = ('1' * 64); files = $core.files; receiptLast = $true }
    $divergentReceiptHash = Get-LowerSha256 (Get-CanonicalJsonBytes $divergentCore)
    Write-Utf8NoBom (Join-Path $root 'receipt.json') (([ordered]@{ schemaVersion = $divergentCore.schemaVersion; sourceRevision = $divergentCore.sourceRevision; productIds = $divergentCore.productIds; cliSha256 = $divergentCore.cliSha256; desktopSha256 = $divergentCore.desktopSha256; guestAgentSha256 = $divergentCore.guestAgentSha256; files = $divergentCore.files; receiptLast = $true; receiptSha256 = $divergentReceiptHash }) | ConvertTo-Json -Depth 30)
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $divergentReceiptHash -SourceRevision $sourceRevision } 'divergent guest-agent receipt identity'
    [IO.File]::WriteAllBytes((Join-Path $root 'receipt.json'), $originalReceipt)

    Write-Utf8NoBom (Join-Path $root 'unexpected.txt') 'extra'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision } 'an extra file'
    Remove-Item -LiteralPath (Join-Path $root 'unexpected.txt') -Force
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'drifted'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision } 'drifted executable bytes'
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixture:aiw.exe'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 ('0' * 64) -SourceRevision $sourceRevision } 'an independently supplied receipt mismatch'
    Remove-Item -LiteralPath (Join-Path $root 'product\notepad-plus-plus\project.yaml') -Force
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision } 'a missing payload'
    Write-Host 'Desktop package verifier contract passed.' -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    if ($hadInheritedLastExitCode) { $global:LASTEXITCODE = $inheritedLastExitCode } else { Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
}
