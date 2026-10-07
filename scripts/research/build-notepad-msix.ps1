#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PortableArchive,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Research-only closed recipe. Never installs or executes the application.
$sourceHash = 'b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66'
$toolHash = '00fff202b71c1266b8c3899701e42b5468ea153b2b33a0a47215fe27695f16d0'
$tool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe'
$publisher = 'CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US'

function Assert-OrdinaryPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse path refused' }
        $parent = Split-Path -Path $item.FullName -Parent
        $item = if ($parent -and $parent -ne $item.FullName) { Get-Item -LiteralPath $parent -Force } else { $null }
    }
}
function Get-StreamHash([IO.Stream]$Stream) {
    $Stream.Position = 0
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Stream)).ToLowerInvariant()
    $Stream.Position = 0
    return $hash
}
function Get-Inventory([string]$Root) {
    return @(Get-ChildItem -LiteralPath $Root -File -Recurse | ForEach-Object {
        [ordered]@{ path = [IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/'); sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant() }
    } | Sort-Object { $_.path })
}

$archivePath = (Resolve-Path -LiteralPath $PortableArchive).ProviderPath
$output = [IO.Path]::GetFullPath($OutputDirectory)
$parent = Split-Path -Path $output -Parent
Assert-OrdinaryPath $archivePath
Assert-OrdinaryPath $parent
if (Test-Path -LiteralPath $output) { throw 'A fresh output directory is required' }
Assert-OrdinaryPath $tool
$heldTool = [IO.File]::Open($tool, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
if ((Get-StreamHash $heldTool) -cne $toolHash) { throw 'Pinned SDK tool differs' }
$signature = Get-AuthenticodeSignature -LiteralPath $tool
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Microsoft Corporation') { throw 'SDK publisher verification failed' }

$held = [IO.File]::Open($archivePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    if ($held.Length -ne 8232940 -or (Get-StreamHash $held) -cne $sourceHash) { throw 'Only the pinned Notepad++ 8.9.8 x64 portable archive is supported' }
    $zip = [IO.Compression.ZipArchive]::new($held, [IO.Compression.ZipArchiveMode]::Read, $true)
    try {
        if ($zip.Entries.Count -ne 231 -or ($zip.Entries | Measure-Object Length -Sum).Sum -ne 27100036) { throw 'Pinned archive inventory differs' }
        # Admit every name before extraction. Case aliases, ADS, traversal and links fail closed.
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.TrimEnd('/')
            if (!$name -or $name.Contains('\') -or $name.Contains(':') -or $name.StartsWith('/') -or @($name.Split('/') | Where-Object { $_ -in @('', '.', '..') -or $_.EndsWith('.') -or $_.EndsWith(' ') }).Count -gt 0 -or !$names.Add($name) -or (($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000) { throw 'Unsafe archive entry refused' }
        }
        New-Item -ItemType Directory -Path $output | Out-Null
        $layout = Join-Path $output 'layout'
        $app = Join-Path $layout 'Application'
        New-Item -ItemType Directory -Path $app | Out-Null
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $destination = Join-Path $app $entry.FullName
            [IO.Directory]::CreateDirectory((Split-Path $destination -Parent)) | Out-Null
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose(); $inputStream.Dispose() }
        }
    } finally { $zip.Dispose() }
    $sourceInventory = Get-Inventory $app
    $localConfig = Join-Path $app 'doLocalConf.xml'
    $removedHash = (Get-FileHash -LiteralPath $localConfig).Hash.ToLowerInvariant()
    # MSIX installation is immutable: this explicit adaptation selects per-user configuration.
    Remove-Item -LiteralPath $localConfig
    $assets = Join-Path $layout 'Assets'
    New-Item -ItemType Directory -Path $assets | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot '..\..\gui\icons\icon.png') -Destination (Join-Path $assets 'Research.png')
    $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap uap10 rescap">
  <Identity Name="AIWResearch.NotepadPP" Publisher="$publisher" Version="8.9.8.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Notepad++ AIW packaging research</DisplayName><PublisherDisplayName>Nathan McNulty</PublisherDisplayName><Logo>Assets\Research.png</Logo></Properties>
  <Resources><Resource Language="en-us" /></Resources>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.26100.0" MaxVersionTested="10.0.26100.0" /></Dependencies>
  <Applications><Application Id="Notepad" Executable="Application\notepad++.exe" uap10:RuntimeBehavior="packagedClassicApp" uap10:TrustLevel="mediumIL"><uap:VisualElements DisplayName="Notepad++ AIW packaging research" Description="Fixed MSIX lifecycle research; full trust, not AppContainer" Square150x150Logo="Assets\Research.png" Square44x44Logo="Assets\Research.png" BackgroundColor="transparent" /></Application></Applications>
  <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
</Package>
"@
    [IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $manifest, [Text.UTF8Encoding]::new($false))
    $package = Join-Path $output 'AIWResearch.NotepadPP.8.9.8.0.x64.msix'
    $psi = [Diagnostics.ProcessStartInfo]::new($tool)
    foreach ($argument in @('pack', '/d', $layout, '/p', $package, '/h', 'SHA256')) { $psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($psi)
    try {
    $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
    if (!$process.WaitForExit(60000)) { $process.Kill(); throw 'Assembly deadline exceeded; preserve output' }
    [IO.File]::WriteAllText((Join-Path $output 'makeappx.stdout.txt'), $stdout.GetAwaiter().GetResult())
    [IO.File]::WriteAllText((Join-Path $output 'makeappx.stderr.txt'), $stderr.GetAwaiter().GetResult())
    if ($process.ExitCode -ne 0) { throw "MakeAppx failed with $($process.ExitCode); inspect retained logs" }
    $toolPid = $process.Id
    $toolExit = $process.ExitCode
    } finally { $process.Dispose() }
    $record = [ordered]@{
        schemaVersion = 'aiw.dev/research-msix-assembly/v0alpha1'; researchOnly = $true
        deliveryModel = 'containedMsix'; runtimeBoundary = 'mediumIlFullTrust'
        source = [ordered]@{ url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8/npp.8.9.8.portable.x64.zip'; sha256 = $sourceHash; sizeBytes = $held.Length; inventory = $sourceInventory }
        adaptation = [ordered]@{ removed = 'Application/doLocalConf.xml'; sha256 = $removedHash; reason = 'Select per-user configuration instead of the immutable installation directory' }
        packageIdentity = 'AIWResearch.NotepadPP'; version = '8.9.8.0'; publisher = $publisher
        tool = [ordered]@{ sha256 = $toolHash; version = (Get-Item $tool).VersionInfo.FileVersion; pid = $toolPid; exitCode = $toolExit }
        payloadInventory = Get-Inventory $layout
        package = [ordered]@{ path = $package; sha256 = (Get-FileHash -LiteralPath $package).Hash.ToLowerInvariant(); sizeBytes = (Get-Item $package).Length; signingStatus = 'unsigned' }
        lifecycleAcceptance = 'notRun'; isolationAcceptance = 'notMeasured'
    }
    # Terminal record last; a partial directory is never accepted as completed assembly.
    $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $output 'assembly.json') -Encoding utf8NoBOM
    [pscustomobject]@{ package = $package; sha256 = $record.package.sha256; signed = $false; lifecycleAcceptance = 'notRun' } | ConvertTo-Json -Compress
} finally { $held.Dispose() }
} finally { $heldTool.Dispose() }
