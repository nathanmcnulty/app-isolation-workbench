[CmdletBinding(DefaultParameterSetName = 'Export')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Export')] [string]$PackageRoot,
    [Parameter(Mandatory, ParameterSetName = 'Expand')] [string]$ArchivePath,
    [Parameter(Mandatory, ParameterSetName = 'Expand')] [ValidatePattern('^[0-9a-f]{64}$')] [string]$ArchiveSha256,
    [Parameter(Mandatory)] [string]$OutputDirectory,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{64}$')] [string]$ReceiptSha256,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision,
    [switch]$RequirePublisherSignature
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$verifier = Join-Path $PSScriptRoot 'verify-desktop-package.ps1'
$allowedPaths = @('receipt.json', 'aiw.exe', 'aiw-desktop.exe', 'README.txt', 'LICENSE', 'verify-desktop-package.ps1',
    'product/notepad-plus-plus/manifest.json', 'product/notepad-plus-plus/project.yaml', 'product/notepad-plus-plus/tools/aiw-guest-agent.exe',
    'product/notepad-plus-plus-interactive/manifest.json', 'product/notepad-plus-plus-interactive/project.yaml', 'product/notepad-plus-plus-interactive/tools/aiw-guest-agent.exe',
    'product/bambu-studio/manifest.json', 'product/bambu-studio/project.json', 'product/bambu-studio/tools/aiw-guest-agent.exe')
$maximumFileBytes = 128MB
$maximumArchiveBytes = 512MB
$handoffLocks = [Collections.Generic.List[IO.FileStream]]::new()
$signedPackagePaths = @('aiw.exe', 'aiw-desktop.exe', 'verify-desktop-package.ps1',
    'product/notepad-plus-plus/tools/aiw-guest-agent.exe',
    'product/notepad-plus-plus-interactive/tools/aiw-guest-agent.exe',
    'product/bambu-studio/tools/aiw-guest-agent.exe')

function Resolve-LocalPath([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    if ($resolved -notmatch '^[A-Za-z]:\\' -or $resolved.Substring(2).Contains(':')) { throw 'Use an ordinary local filesystem path' }
    return $resolved.TrimEnd('\')
}
function Assert-OrdinaryAncestors([string]$Path) {
    $current = $Path
    while ($current) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse paths are not supported for desktop archive handoffs' }
        $current = Split-Path -Parent $current
    }
}
function Get-StreamHash([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Copy-BoundedStream([IO.Stream]$InputStream, [IO.Stream]$OutputStream, [long]$ExpectedSize) {
    if ($ExpectedSize -lt 0 -or $ExpectedSize -gt $maximumFileBytes) { throw 'Archive file exceeds the bounded handoff contract' }
    $buffer = New-Object byte[] 65536
    [long]$copied = 0
    while (($read = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $copied += $read
        if ($copied -gt $ExpectedSize) { throw 'Archive file expanded beyond its declared size' }
        $OutputStream.Write($buffer, 0, $read)
    }
    if ($copied -ne $ExpectedSize) { throw 'Archive file length differs from its declared size' }
}
function Copy-PackageFile([string]$Root, [string]$Relative, [string]$Destination) {
    if ($allowedPaths -cnotcontains $Relative) { throw 'Package file is outside the closed handoff contract' }
    $source = Join-Path $Root $Relative
    Assert-OrdinaryAncestors $source
    $inputFile = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($Relative -ceq 'receipt.json' -and $inputFile.Length -gt 1MB) { throw 'Package receipt exceeds the bounded contract' }
        [IO.Directory]::CreateDirectory((Split-Path -Parent $Destination)) | Out-Null
        $outputFile = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { Copy-BoundedStream $inputFile $outputFile $inputFile.Length }
        finally { $outputFile.Dispose() }
    }
    finally { $inputFile.Dispose() }
}
function Assert-Publisher([string]$Path) {
    Assert-OrdinaryAncestors $Path
    $held = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path
        if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
            $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate -or
            $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Nathan McNulty') {
            throw 'Signed desktop handoff requires valid timestamped Authenticode from Nathan McNulty'
        }
    } finally { $held.Dispose() }
}
function Verify-Package([string]$Root) {
    # Always execute the repository-owned verifier, never code extracted from the ZIP.
    $result = & $verifier -PackageRoot $Root -ReceiptSha256 $ReceiptSha256 -SourceRevision $SourceRevision | ConvertFrom-Json
    if ($result.exactInventory -ne $true) { throw 'Desktop package inventory did not verify' }
    if ($RequirePublisherSignature) {
        foreach ($relative in $signedPackagePaths) { Assert-Publisher (Join-Path $Root $relative) }
    }
}
function Expand-HeldArchive([IO.FileStream]$Stream, [string]$Destination) {
    if ($Stream.Length -gt $maximumArchiveBytes) { throw 'Archive exceeds the bounded handoff contract' }
    $actualHash = Get-StreamHash $Stream
    if ($actualHash -cne $ArchiveSha256) { throw 'Archive differs from the independently supplied SHA-256' }
    $Stream.Position = 0
    $zip = [IO.Compression.ZipArchive]::new($Stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        if ($zip.Entries.Count -gt $allowedPaths.Count) { throw 'Archive contains too many entries' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [long]$total = 0
        foreach ($entry in $zip.Entries) {
            if ($allowedPaths -cnotcontains $entry.FullName -or -not $seen.Add($entry.FullName)) { throw 'Archive contains an unexpected or duplicate path' }
            $total += $entry.Length
            if ($entry.Length -gt $maximumFileBytes -or $total -gt $maximumArchiveBytes -or ($entry.FullName -ceq 'receipt.json' -and $entry.Length -gt 1MB)) { throw 'Archive contents exceed the bounded handoff contract' }
        }
        foreach ($entry in $zip.Entries) {
            $destinationFile = Join-Path $Destination $entry.FullName
            [IO.Directory]::CreateDirectory((Split-Path -Parent $destinationFile)) | Out-Null
            $entryStream = $entry.Open()
            try {
                $file = [IO.File]::Open($destinationFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try { Copy-BoundedStream $entryStream $file $entry.Length }
                finally { $file.Dispose() }
            }
            finally { $entryStream.Dispose() }
        }
    }
    finally { $zip.Dispose() }
    Verify-Package $Destination
}

$output = Resolve-LocalPath $OutputDirectory
$parent = Split-Path -Parent $output
Assert-OrdinaryAncestors $parent
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Output parent must already exist' }
if (Test-Path -LiteralPath $output) { throw 'Output already exists; choose a fresh directory' }
$stageLeaf = "aiw-desktop-handoff-$([guid]::NewGuid().ToString('N'))"
$stage = Join-Path $parent $stageLeaf
New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
try {
    if ($RequirePublisherSignature) {
        # Hold the authenticated tools against replacement through invocation and
        # copying. Authenticating only after verifier execution is too late.
        foreach ($tool in @($PSCommandPath, $verifier)) {
            Assert-OrdinaryAncestors $tool
            $handoffLocks.Add([IO.File]::Open($tool, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read))
            Assert-Publisher $tool
        }
    }
    if ($PSCmdlet.ParameterSetName -ceq 'Export') {
        $root = Resolve-LocalPath $PackageRoot
        Assert-OrdinaryAncestors $root
        if ($output.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Archive output must be outside the package' }
        Verify-Package $root
        $payload = Join-Path $stage 'payload'
        Copy-PackageFile $root 'receipt.json' (Join-Path $payload 'receipt.json')
        $receipt = Get-Content -LiteralPath (Join-Path $payload 'receipt.json') -Raw | ConvertFrom-Json
        foreach ($record in $receipt.files) { Copy-PackageFile $root ([string]$record.path) (Join-Path $payload ([string]$record.path)) }
        Verify-Package $payload
        $zipPath = Join-Path $stage 'aiw-desktop.zip'
        $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
            try {
                foreach ($relative in @('receipt.json') + @($receipt.files | ForEach-Object { [string]$_.path })) {
                    $entry = $zip.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
                    $entry.LastWriteTime = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
                    $inputFile = [IO.File]::OpenRead((Join-Path $payload $relative))
                    try { $entryStream = $entry.Open(); try { Copy-BoundedStream $inputFile $entryStream $inputFile.Length } finally { $entryStream.Dispose() } }
                    finally { $inputFile.Dispose() }
                }
            }
            finally { $zip.Dispose() }
            $stream.Position = 0
            $ArchiveSha256 = Get-StreamHash $stream
            $stream.Position = 0
            $roundTrip = Join-Path $stage 'round-trip'
            Expand-HeldArchive $stream $roundTrip
            $manifest = [ordered]@{ schemaVersion = 'aiw.dev/desktop-distribution/v0alpha1'; sourceRevision = $SourceRevision; archive = [ordered]@{ fileName = 'aiw-desktop.zip'; sizeBytes = $stream.Length; sha256 = $ArchiveSha256; format = 'zip' }; receiptSha256 = $ReceiptSha256; receiptFileSha256 = (Get-FileHash -LiteralPath (Join-Path $payload 'receipt.json') -Algorithm SHA256).Hash.ToLowerInvariant(); verifierSha256 = (Get-FileHash -LiteralPath (Join-Path $payload 'verify-desktop-package.ps1') -Algorithm SHA256).Hash.ToLowerInvariant(); signingStatus = 'unsignedDevelopmentPreview'; authenticity = 'notEstablished' }
        }
        finally { $stream.Dispose() }
        foreach ($owned in @($payload, $roundTrip)) {
            Assert-OrdinaryAncestors $owned
            if (Get-ChildItem -LiteralPath $owned -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Refusing cleanup of a payload containing a reparse point' }
            Remove-Item -LiteralPath $owned -Recurse -Force
        }
        # These are handoff tools, outside the unchanged closed application ZIP.
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $stage 'desktop-package-archive.ps1')
        Copy-Item -LiteralPath $verifier -Destination (Join-Path $stage 'verify-desktop-package.ps1')
        if ($RequirePublisherSignature) {
            foreach ($name in @('desktop-package-archive.ps1', 'verify-desktop-package.ps1')) { Assert-Publisher (Join-Path $stage $name) }
            $manifest.signingStatus = 'publisherSignatureVerified'
            # Authenticode covers these files, not the unsigned receipt, project
            # assets, ZIP, or distribution record. Independent hashes still bind
            # the exact handoff; they are not a publisher signature over it.
            $manifest.publisherSignaturesVerified = $true
            $manifest.publisher = 'Nathan McNulty'
            $manifest.signedPackagePaths = $signedPackagePaths
        }
        $manifest.handoffTools = @('desktop-package-archive.ps1', 'verify-desktop-package.ps1') | ForEach-Object {
            [ordered]@{ fileName = $_; sha256 = (Get-FileHash -LiteralPath (Join-Path $stage $_) -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
        [IO.File]::WriteAllText((Join-Path $stage 'distribution.json'), ($manifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    }
    else {
        $archive = Resolve-LocalPath $ArchivePath
        Assert-OrdinaryAncestors $archive
        $stream = [IO.File]::Open($archive, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { Expand-HeldArchive $stream $stage }
        finally { $stream.Dispose() }
    }
    [IO.Directory]::Move($stage, $output)
    [ordered]@{ schemaVersion = 'aiw.dev/desktop-archive-result/v0alpha1'; operation = $PSCmdlet.ParameterSetName; outputDirectory = $output; archiveSha256 = $ArchiveSha256; receiptSha256 = $ReceiptSha256; sourceRevision = $SourceRevision; exactInventory = $true; authenticity = 'notEstablished'; publisherSignaturesVerified = [bool]$RequirePublisherSignature; signedPackagePaths = $(if ($RequirePublisherSignature) { $signedPackagePaths } else { @() }) } | ConvertTo-Json -Compress
}
finally {
    foreach ($heldTool in $handoffLocks) { $heldTool.Dispose() }
    if (Test-Path -LiteralPath $stage) {
        if ((Split-Path -Parent $stage) -cne $parent -or (Split-Path -Leaf $stage) -cne $stageLeaf) { throw 'Refusing cleanup outside the owned handoff stage' }
        Assert-OrdinaryAncestors $stage
        $reparse = Get-ChildItem -LiteralPath $stage -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
        if ($reparse) { throw 'Refusing cleanup of a stage containing a reparse point' }
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
