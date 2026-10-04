[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$PackageRoot,
    [Parameter(Mandatory)] [string]$ReceiptSha256,
    [Parameter(Mandatory)] [string]$SourceRevision
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$handoff = Join-Path $PSScriptRoot 'desktop-package-archive.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "aiw-desktop-archive-tests-$([guid]::NewGuid().ToString('N'))"
$identity = @{ ReceiptSha256 = $ReceiptSha256; SourceRevision = $SourceRevision }
function Assert-Rejected([scriptblock]$Operation, [string]$Expected, [string]$Destination) {
    $failure = $null
    try { & $Operation | Out-Null } catch { $failure = $_.Exception.Message }
    if (-not $failure -or -not $failure.Contains($Expected)) { throw "Archive control expected '$Expected', got '$failure'" }
    if (Test-Path -LiteralPath $Destination) { throw 'Rejected archive published a destination' }
    if (Get-ChildItem -LiteralPath $root -Filter 'aiw-desktop-handoff-*') { throw 'Rejected archive left a staging directory' }
}
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $exportRoot = Join-Path $root 'distribution'
    $export = & $handoff -PackageRoot $PackageRoot -OutputDirectory $exportRoot @identity | ConvertFrom-Json
    $archive = Join-Path $exportRoot 'aiw-desktop.zip'
    $manifest = Get-Content -LiteralPath (Join-Path $exportRoot 'distribution.json') -Raw | ConvertFrom-Json
    if ($export.exactInventory -ne $true -or $manifest.archive.sha256 -cne $export.archiveSha256 -or $manifest.authenticity -cne 'notEstablished') { throw 'Export did not publish its verified unsigned identities' }
    foreach ($tool in $manifest.handoffTools) { if ((Get-FileHash -LiteralPath (Join-Path $exportRoot $tool.fileName) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $tool.sha256) { throw 'Handoff tool differs from its recorded identity' } }
    $expanded = Join-Path $root 'expanded'
    $expand = & (Join-Path $exportRoot 'desktop-package-archive.ps1') -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory $expanded @identity | ConvertFrom-Json
    if ($expand.exactInventory -ne $true -or (Get-FileHash -LiteralPath (Join-Path $expanded 'receipt.json')).Hash -cne (Get-FileHash -LiteralPath (Join-Path $PackageRoot 'receipt.json')).Hash) { throw 'Archive round trip changed the receipt' }
    $preserved = [IO.File]::ReadAllBytes((Join-Path $expanded 'aiw.exe'))
    try { & $handoff -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory $expanded @identity | Out-Null; throw 'Existing destination was accepted' }
    catch { if (-not $_.Exception.Message.Contains('Output already exists')) { throw } }
    if ([Convert]::ToBase64String($preserved) -cne [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $expanded 'aiw.exe')))) { throw 'Existing destination changed' }
    $destination = Join-Path $root 'wrong-archive'
    Assert-Rejected { & $handoff -ArchivePath $archive -ArchiveSha256 ('0' * 64) -OutputDirectory $destination @identity } 'independently supplied SHA-256' $destination
    $destination = Join-Path $root 'wrong-receipt'
    Assert-Rejected { & $handoff -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory $destination -ReceiptSha256 ('0' * 64) -SourceRevision $SourceRevision } 'independently supplied hash' $destination
    $destination = Join-Path $root 'wrong-source'
    Assert-Rejected { & $handoff -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory $destination -ReceiptSha256 $ReceiptSha256 -SourceRevision ('f' * 40) } 'closed desktop package contract' $destination
    foreach ($case in @('duplicate', 'traversal', 'tampered-payload', 'missing-payload')) {
        $badArchive = Join-Path $root "$case.zip"
        Copy-Item -LiteralPath $archive -Destination $badArchive
        $file = [IO.File]::Open($badArchive, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Update, $true)
            try {
                if ($case -eq 'missing-payload' -or $case -eq 'tampered-payload') { $zip.GetEntry('aiw.exe').Delete() }
                if ($case -ne 'missing-payload') {
                    $name = if ($case -eq 'traversal') { '../escaped.txt' } else { 'aiw.exe' }
                    $entry = $zip.CreateEntry($name)
                    $writer = [IO.StreamWriter]::new($entry.Open())
                    try { $writer.Write('not the verified executable') } finally { $writer.Dispose() }
                }
            }
            finally { $zip.Dispose() }
        }
        finally { $file.Dispose() }
        $hash = (Get-FileHash -LiteralPath $badArchive -Algorithm SHA256).Hash.ToLowerInvariant()
        $destination = Join-Path $root $case
        $expected = switch ($case) { 'duplicate' { 'Archive contains' }; 'traversal' { 'Archive contains' }; 'tampered-payload' { 'Package payload' }; 'missing-payload' { 'is missing' } }
        Assert-Rejected { & $handoff -ArchivePath $badArchive -ArchiveSha256 $hash -OutputDirectory $destination @identity } $expected $destination
    }
    if (Test-Path -LiteralPath (Join-Path $root 'escaped.txt')) { throw 'Traversal wrote outside the stage' }
    $junction = Join-Path $root 'junction'
    try {
        New-Item -ItemType Junction -Path $junction -Target $expanded | Out-Null
        $destination = Join-Path $junction 'rejected'
        Assert-Rejected { & $handoff -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory $destination @identity } 'Reparse paths' $destination
    }
    finally { if (Test-Path -LiteralPath $junction) { Remove-Item -LiteralPath $junction -Force } }
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $output51 = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $handoff -ArchivePath $archive -ArchiveSha256 $export.archiveSha256 -OutputDirectory (Join-Path $root 'powershell51') -ReceiptSha256 $ReceiptSha256 -SourceRevision $SourceRevision | Out-String
        if ($LASTEXITCODE -ne 0 -or ($output51 | ConvertFrom-Json).exactInventory -ne $true) { throw 'Windows PowerShell 5.1 archive handoff failed' }
    }
    Write-Host 'Desktop archive round trip and refusal controls passed.' -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $root) {
        $resolved = [IO.Path]::GetFullPath($root)
        if ((Split-Path -Parent $resolved) -cne ([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')) -or (Split-Path -Leaf $resolved) -notmatch '^aiw-desktop-archive-tests-[0-9a-f]{32}$') { throw 'Refusing cleanup outside owned archive fixtures' }
        if (Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'Refusing fixture cleanup with reparse children' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
