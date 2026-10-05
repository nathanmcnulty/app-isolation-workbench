[CmdletBinding()]
param([switch]$CheckSignedAssembly)

$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify-desktop-package.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "aiw-desktop-verifier-$([guid]::NewGuid().ToString('N'))"
$sourceRevision = if ($CheckSignedAssembly) { (git -C (Split-Path -Parent $PSScriptRoot) rev-parse HEAD).Trim() } else { '0123456789abcdef0123456789abcdef01234567' }
$hadInheritedLastExitCode = Test-Path -LiteralPath Variable:LASTEXITCODE
$inheritedLastExitCode = if ($hadInheritedLastExitCode) { $global:LASTEXITCODE } else { $null }

function Write-Utf8NoBom([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false)) }
function Get-CanonicalJsonBytes([object]$Value) { return ,([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress))) }
function Get-LowerSha256([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
function Sort-OrdinalRecords([object[]]$Items) {
    $sorted = [Collections.Generic.List[object]]::new()
    foreach ($item in $Items) {
        $index = 0
        while ($index -lt $sorted.Count -and [StringComparer]::Ordinal.Compare([string]$sorted[$index].path, [string]$item.path) -lt 0) { $index++ }
        $sorted.Insert($index, $item)
    }
    return $sorted.ToArray()
}
function Assert-Rejected([scriptblock]$Operation, [string]$Case) { try { & $Operation | Out-Null } catch { return }; throw "Desktop package verifier accepted $Case" }
function Write-Receipt([string]$Schema, [string[]]$Products, [string]$GuestHash) {
    $rootPrefix = $root.TrimEnd('\') + '\'
    $records = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -cne 'receipt.json' } | ForEach-Object { [ordered]@{ path = $_.FullName.Substring($rootPrefix.Length).Replace('\', '/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
    $records = @(Sort-OrdinalRecords $records)
    $core = [ordered]@{ schemaVersion = $Schema; sourceRevision = $sourceRevision; productIds = $Products; cliSha256 = (Get-FileHash -LiteralPath (Join-Path $root 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant(); desktopSha256 = (Get-FileHash -LiteralPath (Join-Path $root 'aiw-desktop.exe') -Algorithm SHA256).Hash.ToLowerInvariant(); guestAgentSha256 = $GuestHash; files = $records; receiptLast = $true }
    $hash = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    Write-Utf8NoBom (Join-Path $root 'receipt.json') (([ordered]@{ schemaVersion = $core.schemaVersion; sourceRevision = $core.sourceRevision; productIds = $core.productIds; cliSha256 = $core.cliSha256; desktopSha256 = $core.desktopSha256; guestAgentSha256 = $core.guestAgentSha256; files = $core.files; receiptLast = $true; receiptSha256 = $hash }) | ConvertTo-Json -Depth 30)
    return [pscustomobject]@{ hash = $hash; records = $records; core = $core }
}

try {
    $paths = @(
        'aiw.exe', 'aiw-desktop.exe', 'README.txt', 'LICENSE', 'verify-desktop-package.ps1',
        'product/notepad-plus-plus/manifest.json', 'product/notepad-plus-plus/project.yaml', 'product/notepad-plus-plus/tools/aiw-guest-agent.exe',
        'product/notepad-plus-plus-interactive/manifest.json', 'product/notepad-plus-plus-interactive/project.yaml', 'product/notepad-plus-plus-interactive/tools/aiw-guest-agent.exe',
        'product/bambu-studio/manifest.json', 'product/bambu-studio/project.json', 'product/bambu-studio/tools/aiw-guest-agent.exe'
    )
    foreach ($path in $paths) { New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $root $path)) -Force | Out-Null; Write-Utf8NoBom (Join-Path $root $path) "fixture:$path" }
    $guestBytes = [Text.UTF8Encoding]::new($false).GetBytes('fixture:shared-guest')
    foreach ($guestPath in @('product\notepad-plus-plus\tools\aiw-guest-agent.exe', 'product\notepad-plus-plus-interactive\tools\aiw-guest-agent.exe', 'product\bambu-studio\tools\aiw-guest-agent.exe')) { [IO.File]::WriteAllBytes((Join-Path $root $guestPath), $guestBytes) }
    foreach ($product in @(@{ dir = 'notepad-plus-plus'; id = 'notepad-plus-plus-local-settings'; project = 'project.yaml'; scenario = 'install-launch-close' }, @{ dir = 'notepad-plus-plus-interactive'; id = 'notepad-plus-plus-interactive'; project = 'project.yaml'; scenario = 'install-launch-close' }, @{ dir = 'bambu-studio'; id = 'bambu-studio-export'; project = 'project.json'; scenario = 'local-file-export' })) {
        $productRoot = Join-Path $root "product\$($product.dir)"
        $project = Join-Path $productRoot $product.project; $guest = Join-Path $productRoot 'tools\aiw-guest-agent.exe'
        $manifest = [ordered]@{ schemaVersion = 'aiw.dev/admin-product-assets/v0alpha1'; productId = $product.id; projectPath = $product.project; projectSha256 = (Get-FileHash -LiteralPath $project -Algorithm SHA256).Hash.ToLowerInvariant(); guestAgentPath = 'tools/aiw-guest-agent.exe'; scenarioId = $product.scenario; guestAgentSha256 = (Get-FileHash -LiteralPath $guest -Algorithm SHA256).Hash.ToLowerInvariant() }
        Write-Utf8NoBom (Join-Path $productRoot 'manifest.json') ($manifest | ConvertTo-Json -Depth 10)
    }
    $guestHash = (Get-FileHash -LiteralPath (Join-Path $root 'product\notepad-plus-plus\tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $written = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    $receiptHash = $written.hash
    $records = $written.records
    $core = $written.core

    $valid = & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision | ConvertFrom-Json
    if ($valid.exactInventory -ne $true -or $valid.filesVerified -ne $records.Count) { throw 'Valid desktop package fixture did not verify' }
    $normalizedRoot = & $verifier -PackageRoot ($root + '\') -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision | ConvertFrom-Json
    if ($normalizedRoot.exactInventory -ne $true) { throw 'Trailing-separator package root did not verify' }
    & (Join-Path $PSScriptRoot 'test-desktop-package-archive.ps1') -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision

    $signedExport = Join-Path ([IO.Path]::GetTempPath()) "aiw-signed-refusal-$([guid]::NewGuid().ToString('N'))"
    Assert-Rejected { & (Join-Path $PSScriptRoot 'desktop-package-archive.ps1') -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision -OutputDirectory $signedExport -RequirePublisherSignature } 'unsigned payload requested as an authenticated handoff'
    if (Test-Path -LiteralPath $signedExport) { throw 'Unsigned handoff was published despite signature refusal' }
    if ($CheckSignedAssembly) {
        # Kept outside the unsigned package's closed inventory.
        $signedInputs = $root + '-signed-inputs'
        New-Item -ItemType Directory -Path $signedInputs | Out-Null
        try {
            foreach ($name in @('aiw.exe', 'aiw-desktop.exe', 'verify-desktop-package.ps1')) { Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $signedInputs $name) }
            Copy-Item -LiteralPath (Join-Path $root 'product\notepad-plus-plus\tools\aiw-guest-agent.exe') -Destination (Join-Path $signedInputs 'aiw-guest-agent.exe')
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'desktop-package-archive.ps1') -Destination (Join-Path $signedInputs 'desktop-package-archive.ps1')
            $buildFiles = @(Get-ChildItem -LiteralPath $signedInputs -File | ForEach-Object { @{ name = $_.Name; sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
            $buildPath = $root + '-build.json'
            @{ sourceRevision = $sourceRevision; receiptSha256 = $receiptHash; files = $buildFiles } | ConvertTo-Json -Depth 5 | Set-Content $buildPath
            $parameters = @{ UnsignedPackageRoot = $root; UnsignedReceiptSha256 = $receiptHash; SourceRevision = $sourceRevision; SignedArtifactsDirectory = $signedInputs; BuildRecord = $buildPath; OutputDirectory = $root + '-assembled'; EvidenceDirectory = $root + '-evidence' }
            $rejection = $null
            try { & (Join-Path $PSScriptRoot 'assemble-signed-desktop-package.ps1') @parameters | Out-Null } catch { $rejection = $_.Exception.Message }
            if ($rejection -notlike '*requires valid timestamped Authenticode*') { throw "Expected real unsigned-signature refusal, got: $rejection" }
            if (Test-Path -LiteralPath $parameters.OutputDirectory) { throw 'Unsigned assembly published a package' }
            $negative = Get-Content (Join-Path $parameters.EvidenceDirectory 'aiw.exe.signature.json') -Raw | ConvertFrom-Json
            if ($negative.verified -or $negative.signatureStatus -eq 'Valid') { throw 'Unsigned fixture assembly did not retain a truthful signature refusal' }
            $parameters.EvidenceDirectory = $root + '-bad-record-evidence'
            $badBuild = Get-Content $buildPath -Raw | ConvertFrom-Json
            $badBuild.files[0].sha256 = '0' * 64
            $badBuild | ConvertTo-Json -Depth 5 | Set-Content $buildPath
            $rejection = $null
            try { & (Join-Path $PSScriptRoot 'assemble-signed-desktop-package.ps1') @parameters | Out-Null } catch { $rejection = $_.Exception.Message }
            if ($rejection -notlike '*Unsigned signing input differs*' -or (Test-Path -LiteralPath $parameters.EvidenceDirectory)) { throw 'Assembly failed to reject build input drift before signature processing' }
        } finally {
            foreach ($owned in @($signedInputs, ($root + '-evidence'))) {
                if (Test-Path -LiteralPath $owned) {
                    if ((Split-Path -Parent $owned) -ine ([IO.Path]::GetTempPath()).TrimEnd('\') -or -not $owned.StartsWith($root + '-', [StringComparison]::OrdinalIgnoreCase) -or (Get-ChildItem -LiteralPath $owned -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })) { throw 'Unexpected signed fixture cleanup target' }
                    Remove-Item -LiteralPath $owned -Recurse -Force
                }
            }
            if (Test-Path -LiteralPath ($root + '-build.json')) { Remove-Item -LiteralPath ($root + '-build.json') -Force }
        }
    }

    $bambuRoot = Join-Path $root 'product\bambu-studio'
    $bambuFiles = @{}
    foreach ($relative in @('manifest.json', 'project.json', 'tools\aiw-guest-agent.exe')) { $bambuFiles[$relative] = [IO.File]::ReadAllBytes((Join-Path $bambuRoot $relative)) }
    Remove-Item -LiteralPath $bambuRoot -Recurse -Force
    $historical = Write-Receipt 'aiw.dev/desktop-package/v0alpha1' @('notepad-plus-plus', 'notepad-plus-plus-interactive') $guestHash
    $validHistorical = & $verifier -PackageRoot $root -ReceiptSha256 $historical.hash -SourceRevision $sourceRevision | ConvertFrom-Json
    if ($validHistorical.exactInventory -ne $true -or $validHistorical.filesVerified -ne $historical.records.Count) { throw 'Historical v0alpha1 desktop package fixture did not verify' }
    & (Join-Path $PSScriptRoot 'test-desktop-package-archive.ps1') -PackageRoot $root -ReceiptSha256 $historical.hash -SourceRevision $sourceRevision
    foreach ($relative in $bambuFiles.Keys) { New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $bambuRoot $relative)) -Force | Out-Null; [IO.File]::WriteAllBytes((Join-Path $bambuRoot $relative), $bambuFiles[$relative]) }
    $written = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    $receiptHash = $written.hash; $records = $written.records; $core = $written.core

    $wrongProducts = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'wrong-product') $guestHash
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $wrongProducts.hash -SourceRevision $sourceRevision } 'wrong product set'
    $unknownSchema = Write-Receipt 'aiw.dev/desktop-package/v0alpha3' @() $guestHash
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $unknownSchema.hash -SourceRevision $sourceRevision } 'an unknown desktop package schema'
    $written = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    $receiptHash = $written.hash; $records = $written.records; $core = $written.core

    $bambuManifestPath = Join-Path $bambuRoot 'manifest.json'
    $bambuManifestBytes = [IO.File]::ReadAllBytes($bambuManifestPath)
    $bambuManifest = Get-Content -Raw -LiteralPath $bambuManifestPath | ConvertFrom-Json
    $bambuManifest.productId = 'wrong-product'
    Write-Utf8NoBom $bambuManifestPath ($bambuManifest | ConvertTo-Json -Depth 10)
    $wrongIdentity = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $wrongIdentity.hash -SourceRevision $sourceRevision } 'mismatched Bambu product identity'
    [IO.File]::WriteAllBytes($bambuManifestPath, $bambuManifestBytes)

    $bambuManifest = Get-Content -Raw -LiteralPath $bambuManifestPath | ConvertFrom-Json
    $bambuManifest.guestAgentSha256 = ('1' * 64)
    Write-Utf8NoBom $bambuManifestPath ($bambuManifest | ConvertTo-Json -Depth 10)
    $wrongGuest = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $wrongGuest.hash -SourceRevision $sourceRevision } 'mismatched Bambu guest identity'
    [IO.File]::WriteAllBytes($bambuManifestPath, $bambuManifestBytes)
    $written = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    $receiptHash = $written.hash; $records = $written.records; $core = $written.core
    if (($env:OS -eq 'Windows_NT' -or $IsWindows) -and $PSVersionTable.PSVersion.Major -ge 7) {
        $powershell51Output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision | Out-String
        $powershell51Exit = $LASTEXITCODE
        if ($powershell51Exit -ne 0) { throw "Windows PowerShell 5.1 verifier failed with native exit code $powershell51Exit" }
        $powershell51Result = $powershell51Output | ConvertFrom-Json
        if ($powershell51Result.exactInventory -ne $true -or [string]$powershell51Result.receiptSha256 -cne $receiptHash) { throw 'Windows PowerShell 5.1 verifier result differed from the PowerShell 7 result' }
    }
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
    Remove-Item -LiteralPath $bambuRoot -Recurse -Force
    $missingProduct = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $missingProduct.hash -SourceRevision $sourceRevision } 'a missing Bambu product'
    foreach ($relative in $bambuFiles.Keys) { New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $bambuRoot $relative)) -Force | Out-Null; [IO.File]::WriteAllBytes((Join-Path $bambuRoot $relative), $bambuFiles[$relative]) }
    $written = Write-Receipt 'aiw.dev/desktop-package/v0alpha2' @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio') $guestHash
    $receiptHash = $written.hash
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'drifted'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision } 'drifted executable bytes'
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixture:aiw.exe'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 ('0' * 64) -SourceRevision $sourceRevision } 'an independently supplied receipt mismatch'
    Remove-Item -LiteralPath (Join-Path $root 'product\notepad-plus-plus\project.yaml') -Force
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptHash -SourceRevision $sourceRevision } 'a missing payload'
    Write-Host 'Desktop package verifier contract passed.' -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $root) {
        $resolvedRoot = (Get-Item -LiteralPath $root -Force).FullName
        $expectedParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
        if ((Split-Path -Parent $resolvedRoot) -ine $expectedParent -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^aiw-desktop-verifier-[0-9a-f]{32}$' -or
            ((Get-Item -LiteralPath $resolvedRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Refusing cleanup outside the owned desktop verifier fixture'
        }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
    if ($hadInheritedLastExitCode) { $global:LASTEXITCODE = $inheritedLastExitCode } else { Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
}
