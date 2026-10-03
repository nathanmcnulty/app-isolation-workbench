[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$OutputDirectory,
    [Parameter(Mandatory)] [Alias('SourceHead')] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$GuestAgent,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string]$GuestAgentSha256
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$previewBuilder = Join-Path $PSScriptRoot 'build-preview-package.ps1'
$verifier = Join-Path $PSScriptRoot 'verify-desktop-package.ps1'
$output = [IO.Path]::GetFullPath($OutputDirectory)
$targetTriple = 'x86_64-pc-windows-msvc'

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
function Assert-OrdinaryDirectory([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Label is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label is a reparse point: $Path" }
}
function Assert-Source([string]$Expected) {
    $head = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $Expected) { throw "Source HEAD differs from the supplied revision: $head" }
    $status = & git -C $repoRoot status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0) { throw 'Source tree status could not be resolved' }
    if ($status) { throw 'Source checkout must be clean for desktop package assembly' }
}
function Assert-LowerHash([string]$Value, [string]$Label) { if ($Value -notmatch '^[0-9a-f]{64}$') { throw "$Label must be a lowercase SHA-256" } }
function Invoke-Preview([string]$Destination, [string]$Product, [string]$GuestPath, [string]$GuestHash) {
    $previewParameters = @{ OutputDirectory = $Destination; Product = $Product }
    if ($GuestPath) { $previewParameters.GuestAgent = $GuestPath; $previewParameters.GuestAgentSha256 = $GuestHash }
    $targetDirectoryPath = 'Env:CARGO_TARGET_DIR'
    $hadTargetDirectory = Test-Path $targetDirectoryPath
    $originalTargetDirectory = if ($hadTargetDirectory) { (Get-Item $targetDirectoryPath).Value } else { $null }
    try {
        Set-Item -Path $targetDirectoryPath -Value $buildTarget
        & $previewBuilder @previewParameters | Out-Null
    }
    finally {
        if ($hadTargetDirectory) { Set-Item -Path $targetDirectoryPath -Value $originalTargetDirectory }
        else { Remove-Item $targetDirectoryPath -ErrorAction SilentlyContinue }
    }
}
function Remove-OwnedTemporaryRoot([string]$Root, [string]$Parent, [string]$Leaf) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $resolvedRoot = [IO.Path]::GetFullPath($Root)
    if ([IO.Path]::GetDirectoryName($resolvedRoot).TrimEnd('\') -cne $Parent.TrimEnd('\') -or
        [IO.Path]::GetFileName($resolvedRoot) -cne $Leaf -or
        $Leaf -notmatch '^aiw-desktop-package-[0-9a-f]{32}$') {
        throw 'Refusing to remove an unexpected temporary staging root'
    }
    Assert-OrdinaryDirectory $Parent 'Temporary staging parent'
    Assert-OrdinaryDirectory $resolvedRoot 'Temporary staging root'
    $reparse = Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
    if ($reparse) { throw 'Refusing to remove a staging tree containing a reparse point' }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}

Assert-Source $SourceRevision
Assert-OrdinaryDirectory (Split-Path -Parent $output) 'Output parent'
if (Test-Path -LiteralPath $output) { throw "Output directory already exists; choose a fresh path: $output" }
if ($output.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($repoRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Output directory must be outside the source checkout' }
$guiManifest = Join-Path $repoRoot 'gui\Cargo.toml'
if (-not (Test-Path -LiteralPath $guiManifest -PathType Leaf)) { throw "Desktop GUI manifest is missing: $guiManifest" }
Assert-LowerHash $GuestAgentSha256 'GuestAgentSha256'
$GuestAgent = [IO.Path]::GetFullPath($GuestAgent)
if (-not (Test-Path -LiteralPath $GuestAgent -PathType Leaf)) { throw "Guest agent is missing: $GuestAgent" }
$guestItem = Get-Item -LiteralPath $GuestAgent -Force
if (($guestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Guest agent is a reparse point' }
if ((Get-FileHash -LiteralPath $GuestAgent -Algorithm SHA256).Hash.ToLowerInvariant() -cne $GuestAgentSha256) { throw 'Guest agent bytes differ from the independently retained hash' }

$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
Assert-OrdinaryDirectory $tempParent 'Temporary staging parent'
$tempLeaf = "aiw-desktop-package-$([guid]::NewGuid().ToString('N'))"
if ($tempLeaf -notmatch '^aiw-desktop-package-[0-9a-f]{32}$') { throw 'Temporary staging leaf is not a generated GUID name' }
$tempRoot = Join-Path $tempParent $tempLeaf
if ([IO.Path]::GetDirectoryName($tempRoot).TrimEnd('\') -cne $tempParent.TrimEnd('\')) { throw 'Temporary staging root escaped its intended parent' }
$buildTarget = Join-Path $tempRoot 'build'
$builtDesktopSource = Join-Path $buildTarget "$targetTriple\release\aiw-desktop.exe"
$assessmentPreview = Join-Path $tempRoot 'assessment'
$interactivePreview = Join-Path $tempRoot 'interactive'
try {
    New-Item -ItemType Directory -Path $tempRoot -Force:$false | Out-Null
    Assert-OrdinaryDirectory $tempRoot 'Temporary staging root'
    New-Item -ItemType Directory -Path $buildTarget -Force:$false | Out-Null
    Assert-OrdinaryDirectory $buildTarget 'Fresh Cargo target directory'
    Push-Location -LiteralPath $repoRoot
    try {
        $targetRustFlagsName = 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'
        $targetRustFlagsPath = "Env:$targetRustFlagsName"
        $hadTargetRustFlags = Test-Path $targetRustFlagsPath
        $originalTargetRustFlags = if ($hadTargetRustFlags) { (Get-Item $targetRustFlagsPath).Value } else { $null }
        $targetDirectoryPath = 'Env:CARGO_TARGET_DIR'
        $hadTargetDirectory = Test-Path $targetDirectoryPath
        $originalTargetDirectory = if ($hadTargetDirectory) { (Get-Item $targetDirectoryPath).Value } else { $null }
        try {
            Set-Item -Path $targetDirectoryPath -Value ([IO.Path]::GetFullPath($buildTarget))
            $metadataText = & cargo metadata --manifest-path ([IO.Path]::GetFullPath($guiManifest)) --format-version 1 --no-deps --locked | Out-String
            if ($LASTEXITCODE -ne 0) { throw 'GUI Cargo metadata resolution failed' }
            $metadata = $metadataText | ConvertFrom-Json
            $metadataTarget = [IO.Path]::GetFullPath([string]$metadata.target_directory)
            if (-not $metadataTarget.TrimEnd('\').Equals($buildTarget.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { throw "GUI Cargo target directory differs from the fresh target: $metadataTarget" }
            $targetRustFlags = (@($originalTargetRustFlags, '-C target-feature=+crt-static') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
            Set-Item -Path $targetRustFlagsPath -Value $targetRustFlags
            & cargo +stable build --manifest-path ([IO.Path]::GetFullPath($guiManifest)) --locked --release --target $targetTriple | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'release aiw-desktop build failed' }
        }
        finally {
            if ($hadTargetRustFlags) { Set-Item -Path $targetRustFlagsPath -Value $originalTargetRustFlags } else { Remove-Item $targetRustFlagsPath -ErrorAction SilentlyContinue }
            if ($hadTargetDirectory) { Set-Item -Path $targetDirectoryPath -Value $originalTargetDirectory } else { Remove-Item $targetDirectoryPath -ErrorAction SilentlyContinue }
        }
    }
    finally { Pop-Location }
    Assert-Source $SourceRevision
    if (-not (Test-Path -LiteralPath $builtDesktopSource -PathType Leaf)) { throw "Fresh desktop executable is missing: $builtDesktopSource" }
    $desktopItem = Get-Item -LiteralPath $builtDesktopSource -Force
    if (($desktopItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Fresh desktop executable is a reparse point' }
    $desktopHash = (Get-FileHash -LiteralPath $builtDesktopSource -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-Preview $assessmentPreview 'NotepadPlusPlus' $GuestAgent $GuestAgentSha256
    Assert-Source $SourceRevision
    $firstGuest = Join-Path $assessmentPreview 'product\notepad-plus-plus\tools\aiw-guest-agent.exe'
    $firstGuestHash = (Get-FileHash -LiteralPath $firstGuest -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($firstGuestHash -cne $GuestAgentSha256) { throw 'Assessment preview guest-agent bytes differ from the independently retained hash' }
    Invoke-Preview $interactivePreview 'NotepadPlusPlusInteractive' $firstGuest $firstGuestHash
    Assert-Source $SourceRevision

    Assert-OrdinaryDirectory $assessmentPreview 'Assessment preview'
    Assert-OrdinaryDirectory $interactivePreview 'Interactive preview'
    $firstCliHash = (Get-FileHash -LiteralPath (Join-Path $assessmentPreview 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $secondCliHash = (Get-FileHash -LiteralPath (Join-Path $interactivePreview 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($firstCliHash -cne $secondCliHash) { throw 'Preview builds produced different CLI bytes' }
    $secondGuestHash = (Get-FileHash -LiteralPath (Join-Path $interactivePreview 'product\notepad-plus-plus-interactive\tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($secondGuestHash -cne $GuestAgentSha256) { throw 'Interactive preview guest-agent bytes differ from the independently retained hash' }
    if ($firstGuestHash -cne $secondGuestHash) { throw 'Preview builds produced different guest-agent bytes' }
    New-Item -ItemType Directory -Path $output -Force:$false | Out-Null
    foreach ($name in @('aiw.exe', 'LICENSE')) { Copy-Item -LiteralPath (Join-Path $assessmentPreview $name) -Destination (Join-Path $output $name) }
    Copy-Item -LiteralPath $builtDesktopSource -Destination (Join-Path $output 'aiw-desktop.exe')
    Copy-Item -LiteralPath $verifier -Destination (Join-Path $output 'verify-desktop-package.ps1')
    New-Item -ItemType Directory -Path (Join-Path $output 'product') -Force:$false | Out-Null
    foreach ($product in @(@{ source = Join-Path $assessmentPreview 'product\notepad-plus-plus'; name = 'notepad-plus-plus' }, @{ source = Join-Path $interactivePreview 'product\notepad-plus-plus-interactive'; name = 'notepad-plus-plus-interactive' })) {
        Copy-Item -LiteralPath $product.source -Destination (Join-Path $output "product\$($product.name)") -Recurse
    }

    $cliHash = (Get-FileHash -LiteralPath (Join-Path $output 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath (Join-Path $output 'aiw-desktop.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $desktopHash) { throw 'Copied desktop executable changed during assembly' }
    $readme = @"
Application Isolation Workbench — unsigned development GUI

Launch directly from this folder with:
  .\aiw-desktop.exe

This package is an unsigned development build assembled from a fresh GUI and
CLI release build under the declared source revision. The GUI supports the fixed
Notepad++ assessment and interactive document workflows. Select the exact
supported Notepad++ MSI in the GUI, choose a bounded text input for the
interactive workflow, review the complete recipe and plan, type the displayed
approval literal, and press Start separately. The Sandbox is not started by
preparation or approval alone. Results distinguish verified application
functions and cleanup from broader isolation evidence, which remains measured
only where the retained report says it is measured.

Source revision: $SourceRevision
CLI SHA-256: $cliHash
Desktop SHA-256: $desktopHash
Guest agent SHA-256 (retained independently): $GuestAgentSha256
"@
    Write-Utf8NoBom (Join-Path $output 'README.txt') $readme.TrimEnd()

    $payload = @(Get-ChildItem -LiteralPath $output -Recurse -File -Force | Where-Object { $_.FullName -cne (Join-Path $output 'receipt.json') } | ForEach-Object {
        [ordered]@{ path = [IO.Path]::GetRelativePath($output, $_.FullName).Replace('\', '/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    $payload = @(Sort-OrdinalRecords $payload)
    $core = [ordered]@{ schemaVersion = 'aiw.dev/desktop-package/v0alpha1'; sourceRevision = $SourceRevision; productIds = @('notepad-plus-plus', 'notepad-plus-plus-interactive'); cliSha256 = $cliHash; desktopSha256 = $desktopHash; guestAgentSha256 = $GuestAgentSha256; files = $payload; receiptLast = $true }
    $receiptHash = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    Write-Utf8NoBom (Join-Path $output 'receipt.json') (([ordered]@{ schemaVersion = $core.schemaVersion; sourceRevision = $core.sourceRevision; productIds = $core.productIds; cliSha256 = $core.cliSha256; desktopSha256 = $core.desktopSha256; guestAgentSha256 = $core.guestAgentSha256; files = $core.files; receiptLast = $true; receiptSha256 = $receiptHash }) | ConvertTo-Json -Depth 30)
    $verification = (& $verifier -PackageRoot $output -ReceiptSha256 $receiptHash -SourceRevision $SourceRevision | ConvertFrom-Json)
    if ($verification.exactInventory -ne $true) { throw 'Desktop package inventory did not verify' }
    Assert-Source $SourceRevision
    [ordered]@{ schemaVersion = 'aiw.dev/desktop-package/v0alpha1'; sourceRevision = $SourceRevision; packageRoot = $output; receiptSha256 = $receiptHash; cliSha256 = $cliHash; desktopSha256 = $desktopHash; guestAgentSha256 = $GuestAgentSha256; products = @('notepad-plus-plus', 'notepad-plus-plus-interactive'); unsigned = $true; exactInventory = $true } | ConvertTo-Json -Depth 10 -Compress
}
finally {
    Remove-OwnedTemporaryRoot $tempRoot $tempParent $tempLeaf
}
