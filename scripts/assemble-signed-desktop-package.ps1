#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$UnsignedPackageRoot,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string]$UnsignedReceiptSha256,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision,
    [Parameter(Mandatory)] [string]$SignedArtifactsDirectory,
    [Parameter(Mandatory)] [string]$BuildRecord,
    [Parameter(Mandatory)] [string]$OutputDirectory,
    [Parameter(Mandatory)] [string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$products = @('notepad-plus-plus', 'notepad-plus-plus-interactive', 'bambu-studio')
$signedNames = @('aiw.exe', 'aiw-desktop.exe', 'aiw-guest-agent.exe', 'verify-desktop-package.ps1', 'desktop-package-archive.ps1')
$handles = [Collections.Generic.Dictionary[string, IO.FileStream]]::new([StringComparer]::OrdinalIgnoreCase)

function Resolve-OrdinaryPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'Use ordinary local filesystem paths' }
    $ancestor = $full
    while ($ancestor) {
        if (Test-Path -LiteralPath $ancestor) {
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse paths are not supported for signed assembly' }
        }
        $ancestor = Split-Path -Parent $ancestor
    }
    return $full.TrimEnd('\')
}
function Hold-File([string]$Path) {
    $path = Resolve-OrdinaryPath $Path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required input is missing: $path" }
    if ((Get-Item -LiteralPath $path).Length -gt 128MB) { throw 'Input exceeds the signed assembly file bound' }
    if (-not $handles.ContainsKey($path)) { $handles.Add($path, [IO.File]::Open($path, 'Open', 'Read', 'Read')) }
    return $path
}
function Copy-Held([string]$Source, [string]$Destination) {
    $source = Hold-File $Source
    $output = [IO.File]::Open($Destination, 'CreateNew', 'Write', 'None')
    try { $handles[$source].Position = 0; $handles[$source].CopyTo($output) }
    finally { $output.Dispose() }
}
function Write-FreshJson([string]$Path, [object]$Value) {
    $stream = [IO.File]::Open($Path, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 30) + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}
function Hash-File([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

$unsigned = Resolve-OrdinaryPath $UnsignedPackageRoot
$signed = Resolve-OrdinaryPath $SignedArtifactsDirectory
$output = Resolve-OrdinaryPath $OutputDirectory
$evidence = Resolve-OrdinaryPath $EvidenceDirectory
foreach ($newRoot in @($output, $evidence)) {
    if (Test-Path -LiteralPath $newRoot) { throw 'Package and evidence destinations must be fresh' }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $newRoot) -PathType Container)) { throw 'Destination parent must already exist' }
    foreach ($other in @($unsigned, $signed, $repoRoot, $(if ($newRoot -ceq $output) { $evidence } else { $output }))) {
        if ($newRoot.Equals($other, [StringComparison]::OrdinalIgnoreCase) -or
            $newRoot.StartsWith($other.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $other.StartsWith($newRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Assembly roots must not overlap inputs, evidence, or source' }
    }
}
try {
    if ((git -C $repoRoot rev-parse HEAD).Trim() -cne $SourceRevision -or $LASTEXITCODE -ne 0) { throw 'Assembly source differs from the declared revision' }
    if (@(git -C $repoRoot status --porcelain=v1 --untracked-files=all).Count -or $LASTEXITCODE -ne 0) { throw 'Signed assembly requires a clean committed source tree' }
    if (-not (Test-Path -LiteralPath $unsigned -PathType Container) -or -not (Test-Path -LiteralPath $signed -PathType Container)) { throw 'Input roots must be directories' }
    foreach ($item in @(Get-ChildItem -LiteralPath $unsigned -Recurse -Force)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsigned package contains a reparse point' }
        if (-not $item.PSIsContainer) { Hold-File $item.FullName | Out-Null }
    }
    & (Join-Path $PSScriptRoot 'verify-desktop-package.ps1') -PackageRoot $unsigned -ReceiptSha256 $UnsignedReceiptSha256 -SourceRevision $SourceRevision | Out-Null
    $receipt = Get-Content -LiteralPath (Join-Path $unsigned 'receipt.json') -Raw | ConvertFrom-Json
    if ($receipt.schemaVersion -cne 'aiw.dev/desktop-package/v0alpha2') { throw 'Only the current three-product package can be signed' }
    $buildPath = Hold-File $BuildRecord
    if ((Get-Item -LiteralPath $buildPath).Length -gt 16384) { throw 'Signing build record exceeds its bound' }
    $build = Get-Content -LiteralPath $buildPath -Raw | ConvertFrom-Json
    if ($build.sourceRevision -cne $SourceRevision -or $build.receiptSha256 -cne $UnsignedReceiptSha256 -or @($build.files).Count -ne $signedNames.Count) { throw 'Signing build record differs from the unsigned package' }
    $items = @(Get-ChildItem -LiteralPath $signed -Force)
    if ($items.Count -ne $signedNames.Count -or @($items | Where-Object { $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }).Count) { throw 'Signed inputs must be exactly the five fixed ordinary files' }
    foreach ($name in $signedNames) {
        Hold-File (Join-Path $signed $name) | Out-Null
        $records = @($build.files | Where-Object name -CEQ $name)
        $original = if ($name -ceq 'aiw-guest-agent.exe') { Join-Path $unsigned 'product\notepad-plus-plus\tools\aiw-guest-agent.exe' } elseif ($name -ceq 'desktop-package-archive.ps1') { Join-Path $PSScriptRoot $name } else { Join-Path $unsigned $name }
        Hold-File $original | Out-Null
        if ($records.Count -ne 1 -or $records[0].sha256 -cne (Hash-File $original) -or $records[0].sizeBytes -ne (Get-Item -LiteralPath $original).Length) { throw "Unsigned signing input differs from the build record: $name" }
    }
    New-Item -ItemType Directory -Path $evidence | Out-Null
    foreach ($name in $signedNames) {
        & (Join-Path $PSScriptRoot 'verify-signing-control.ps1') -Path (Join-Path $signed $name) -SourceRevision $SourceRevision -OutputFile (Join-Path $evidence "$name.signature.json") | Out-Null
    }
    New-Item -ItemType Directory -Path $output | Out-Null
    $guestHash = Hash-File (Join-Path $signed 'aiw-guest-agent.exe')
    foreach ($record in $receipt.files) {
        $relative = [string]$record.path
        $destination = Join-Path $output $relative
        $parent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        if ($relative -ceq 'README.txt') {
            $text = "App Isolation Workbench - signed alpha candidate`n`nLaunch .\aiw-desktop.exe from this folder. Review and approve the exact plan, then press Start. Sandbox data is temporary; explicitly export required results.`n`nSupported workflows: fixed Notepad++ assessment, interactive document transfer, and Bambu Studio STL-to-3MF export. A passing workflow does not establish broader isolation. This candidate requires testing of these exact signed bytes.`n`nSource revision: $SourceRevision`nPublisher: Nathan McNulty`n"
            [IO.File]::WriteAllText($destination, $text, [Text.UTF8Encoding]::new($false))
        } elseif ($relative -match '^product/[^/]+/manifest\.json$') {
            $manifest = Get-Content -LiteralPath (Join-Path $unsigned $relative) -Raw | ConvertFrom-Json
            if ($manifest.PSObject.Properties.Name -ccontains 'launchProfilePath' -or $manifest.PSObject.Properties.Name -ccontains 'launchProfileSha256') { throw 'Historical guest-bound launch profiles cannot be relabeled after signing' }
            $manifest.guestAgentSha256 = $guestHash
            Write-FreshJson $destination $manifest
        } else {
            $source = if ($relative -match '/tools/aiw-guest-agent\.exe$') { Join-Path $signed 'aiw-guest-agent.exe' } elseif ($relative -cin @('aiw.exe', 'aiw-desktop.exe', 'verify-desktop-package.ps1')) { Join-Path $signed $relative } else { Join-Path $unsigned $relative }
            Copy-Held $source $destination
        }
    }
    $paths = [string[]]@($receipt.files | ForEach-Object { [string]$_.path })
    [Array]::Sort($paths, [StringComparer]::Ordinal)
    $files = @($paths | ForEach-Object { $file = Get-Item -LiteralPath (Join-Path $output $_); [ordered]@{ path = $_; sizeBytes = $file.Length; sha256 = Hash-File $file.FullName } })
    $core = [ordered]@{ schemaVersion = $receipt.schemaVersion; sourceRevision = $SourceRevision; productIds = $products; cliSha256 = Hash-File (Join-Path $output 'aiw.exe'); desktopSha256 = Hash-File (Join-Path $output 'aiw-desktop.exe'); guestAgentSha256 = $guestHash; files = $files; receiptLast = $true }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($core | ConvertTo-Json -Depth 30 -Compress))
    $coreHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
    $core.receiptSha256 = $coreHash
    Write-FreshJson (Join-Path $output 'receipt.json') $core
    & (Join-Path $PSScriptRoot 'verify-desktop-package.ps1') -PackageRoot $output -ReceiptSha256 $coreHash -SourceRevision $SourceRevision | Out-Null
    # Verify final copied bytes as well as the held inputs. No executable runs here.
    foreach ($relative in @('aiw.exe', 'aiw-desktop.exe', 'verify-desktop-package.ps1') + @($products | ForEach-Object { "product/$_/tools/aiw-guest-agent.exe" })) {
        & (Join-Path $PSScriptRoot 'verify-signing-control.ps1') -Path (Join-Path $output $relative) -SourceRevision $SourceRevision -OutputFile (Join-Path $evidence ($relative.Replace('/', '_') + '.copied-signature.json')) | Out-Null
    }
    $result = [ordered]@{ sourceRevision = $SourceRevision; receiptSha256 = $coreHash; unsignedReceiptSha256 = $UnsignedReceiptSha256; packageRoot = $output; signingVerified = $true; runtimeAcceptance = 'pending'; publisher = 'Nathan McNulty' }
    Write-FreshJson (Join-Path $evidence 'assembly.json') $result
    $result | ConvertTo-Json -Compress
} finally { foreach ($handle in $handles.Values) { $handle.Dispose() } }
