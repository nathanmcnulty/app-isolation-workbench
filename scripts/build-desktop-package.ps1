[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$OutputDirectory,
    [Parameter(Mandatory)] [Alias('DesktopExe')] [ValidateNotNullOrEmpty()] [string]$DesktopExecutable,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string]$DesktopExecutableSha256,
    [Parameter(Mandatory)] [Alias('SourceHead')] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision,
    [string]$GuestAgent,
    [ValidatePattern('^[0-9a-f]{64}$')] [string]$GuestAgentSha256
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$previewBuilder = Join-Path $PSScriptRoot 'build-preview-package.ps1'
$verifier = Join-Path $PSScriptRoot 'verify-desktop-package.ps1'
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.Path]::IsPathRooted($DesktopExecutable)) { throw 'DesktopExecutable must be an absolute path' }
$desktopSource = [IO.Path]::GetFullPath($DesktopExecutable)

function Write-Utf8NoBom([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false)) }
function Get-CanonicalJsonBytes([object]$Value) { return ,([Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress))) }
function Get-LowerSha256([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
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
    & $previewBuilder @previewParameters | Out-Null
}

Assert-LowerHash $DesktopExecutableSha256 'DesktopExecutableSha256'
Assert-Source $SourceRevision
Assert-OrdinaryDirectory (Split-Path -Parent $output) 'Output parent'
if (Test-Path -LiteralPath $output) { throw "Output directory already exists; choose a fresh path: $output" }
if ($output.Equals($repoRoot, [StringComparison]::OrdinalIgnoreCase) -or $output.StartsWith($repoRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Output directory must be outside the source checkout' }
if (-not (Test-Path -LiteralPath $desktopSource -PathType Leaf)) { throw "Desktop executable is missing: $desktopSource" }
$desktopItem = Get-Item -LiteralPath $desktopSource -Force
if (($desktopItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Desktop executable is a reparse point' }
if ((Get-FileHash -LiteralPath $desktopSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne $DesktopExecutableSha256) { throw 'Desktop executable bytes differ from the independently supplied hash' }
if (($null -eq $GuestAgent) -xor ($null -eq $GuestAgentSha256)) { throw 'GuestAgent and GuestAgentSha256 must be supplied together' }
if ($GuestAgent) {
    $GuestAgent = [IO.Path]::GetFullPath($GuestAgent); Assert-LowerHash $GuestAgentSha256 'GuestAgentSha256'
    if (-not (Test-Path -LiteralPath $GuestAgent -PathType Leaf)) { throw "Guest agent is missing: $GuestAgent" }
    if ((Get-FileHash -LiteralPath $GuestAgent -Algorithm SHA256).Hash.ToLowerInvariant() -cne $GuestAgentSha256) { throw 'Guest agent bytes differ from the independently supplied hash' }
}

$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
Assert-OrdinaryDirectory $tempParent 'Temporary staging parent'
$tempLeaf = "aiw-desktop-package-$([guid]::NewGuid().ToString('N'))"
if ($tempLeaf -notmatch '^aiw-desktop-package-[0-9a-f]{32}$') { throw 'Temporary staging leaf is not a generated GUID name' }
$tempRoot = Join-Path $tempParent $tempLeaf
if ([IO.Path]::GetDirectoryName($tempRoot).TrimEnd('\') -cne $tempParent.TrimEnd('\')) { throw 'Temporary staging root escaped its intended parent' }
$assessmentPreview = Join-Path $tempRoot 'assessment'
$interactivePreview = Join-Path $tempRoot 'interactive'
try {
    New-Item -ItemType Directory -Path $tempRoot -Force:$false | Out-Null
    Invoke-Preview $assessmentPreview 'NotepadPlusPlus' $GuestAgent $GuestAgentSha256
    Assert-Source $SourceRevision
    $firstGuest = Join-Path $assessmentPreview 'product\notepad-plus-plus\tools\aiw-guest-agent.exe'
    $firstGuestHash = (Get-FileHash -LiteralPath $firstGuest -Algorithm SHA256).Hash.ToLowerInvariant()
    Invoke-Preview $interactivePreview 'NotepadPlusPlusInteractive' $firstGuest $firstGuestHash
    Assert-Source $SourceRevision

    Assert-OrdinaryDirectory $assessmentPreview 'Assessment preview'
    Assert-OrdinaryDirectory $interactivePreview 'Interactive preview'
    $firstCliHash = (Get-FileHash -LiteralPath (Join-Path $assessmentPreview 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $secondCliHash = (Get-FileHash -LiteralPath (Join-Path $interactivePreview 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($firstCliHash -cne $secondCliHash) { throw 'Preview builds produced different CLI bytes' }
    $secondGuestHash = (Get-FileHash -LiteralPath (Join-Path $interactivePreview 'product\notepad-plus-plus-interactive\tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($firstGuestHash -cne $secondGuestHash) { throw 'Preview builds produced different guest-agent bytes' }
    New-Item -ItemType Directory -Path $output -Force:$false | Out-Null
    foreach ($name in @('aiw.exe', 'LICENSE')) { Copy-Item -LiteralPath (Join-Path $assessmentPreview $name) -Destination (Join-Path $output $name) }
    Copy-Item -LiteralPath $desktopSource -Destination (Join-Path $output 'aiw-desktop.exe')
    Copy-Item -LiteralPath $verifier -Destination (Join-Path $output 'verify-desktop-package.ps1')
    New-Item -ItemType Directory -Path (Join-Path $output 'product') -Force:$false | Out-Null
    foreach ($product in @(@{ source = Join-Path $assessmentPreview 'product\notepad-plus-plus'; name = 'notepad-plus-plus' }, @{ source = Join-Path $interactivePreview 'product\notepad-plus-plus-interactive'; name = 'notepad-plus-plus-interactive' })) {
        Copy-Item -LiteralPath $product.source -Destination (Join-Path $output "product\$($product.name)") -Recurse
    }

    $cliHash = (Get-FileHash -LiteralPath (Join-Path $output 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $desktopHash = (Get-FileHash -LiteralPath (Join-Path $output 'aiw-desktop.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($desktopHash -cne $DesktopExecutableSha256) { throw 'Copied desktop executable changed during assembly' }
    $readme = @"
Application Isolation Workbench — unsigned development GUI

Launch directly from this folder with:
  .\aiw-desktop.exe

This package is an unsigned development build. The GUI supports the fixed
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
"@
    Write-Utf8NoBom (Join-Path $output 'README.txt') $readme.TrimEnd()

    $payload = @(Get-ChildItem -LiteralPath $output -Recurse -File -Force | Where-Object { $_.FullName -cne (Join-Path $output 'receipt.json') } | ForEach-Object {
        [ordered]@{ path = [IO.Path]::GetRelativePath($output, $_.FullName).Replace('\', '/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    } | Sort-Object { $_.path })
    $core = [ordered]@{ schemaVersion = 'aiw.dev/desktop-package/v0alpha1'; sourceRevision = $SourceRevision; productIds = @('notepad-plus-plus', 'notepad-plus-plus-interactive'); cliSha256 = $cliHash; desktopSha256 = $desktopHash; files = $payload; receiptLast = $true }
    $receiptHash = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    Write-Utf8NoBom (Join-Path $output 'receipt.json') (([ordered]@{ schemaVersion = $core.schemaVersion; sourceRevision = $core.sourceRevision; productIds = $core.productIds; cliSha256 = $core.cliSha256; desktopSha256 = $core.desktopSha256; files = $core.files; receiptLast = $true; receiptSha256 = $receiptHash }) | ConvertTo-Json -Depth 30)
    $verification = (& $verifier -PackageRoot $output -ReceiptSha256 $receiptHash -SourceRevision $SourceRevision | ConvertFrom-Json)
    if ($verification.exactInventory -ne $true) { throw 'Desktop package inventory did not verify' }
    Assert-Source $SourceRevision
    [ordered]@{ schemaVersion = 'aiw.dev/desktop-package/v0alpha1'; sourceRevision = $SourceRevision; packageRoot = $output; receiptSha256 = $receiptHash; cliSha256 = $cliHash; desktopSha256 = $desktopHash; products = @('notepad-plus-plus', 'notepad-plus-plus-interactive'); unsigned = $true; exactInventory = $true } | ConvertTo-Json -Depth 10 -Compress
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
        if ([IO.Path]::GetDirectoryName($resolvedTempRoot).TrimEnd('\') -cne $tempParent.TrimEnd('\') -or
            [IO.Path]::GetFileName($resolvedTempRoot) -cne $tempLeaf -or
            $tempLeaf -notmatch '^aiw-desktop-package-[0-9a-f]{32}$') {
            throw 'Refusing to remove an unexpected temporary staging root'
        }
        Assert-OrdinaryDirectory $tempParent 'Temporary staging parent'
        Assert-OrdinaryDirectory $resolvedTempRoot 'Temporary staging root'
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
