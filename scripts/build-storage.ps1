#Requires -Version 7.6
#Requires -PSEdition Core
# Read-only preflight for normal Windows builds. Callers set/restore the returned
# CARGO_TARGET_DIR themselves. This policy never creates, cleans or deletes.
function Assert-AiwBuildLocalDirectory([string]$Path) {
    if ($Path -cnotmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':') -or $Path.Contains('/')) {
        throw 'Build cache requires an ordinary absolute local DOS directory'
    }
    if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path)).DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Build cache requires a local fixed volume'
    }
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        try {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($attributes -band [IO.FileAttributes]::Directory) -eq 0) {
                throw 'Build cache path or ancestor is a redirect or non-directory'
            }
        } catch [IO.FileNotFoundException] { } catch [IO.DirectoryNotFoundException] { }
        $current = [IO.Path]::GetDirectoryName($current.TrimEnd('\'))
    }
}

function Test-AiwBuildPathWithin([string]$Path, [string]$Root) {
    $rootPath = $Root.TrimEnd('\')
    return $Path.Equals($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith($rootPath+'\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-AiwBuildFlags([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    # Permit only the canonical target-specific static-CRT setting.
    # Arbitrary compiler flags cannot be proven harmless by substring matching.
    if ($Value -cne '-C target-feature=+crt-static') {
        throw 'Unreviewed Rust flags override the bounded build policy (values omitted)'
    }
}

function Assert-AiwBuildOverrides([string]$Target, [string]$WorkingDirectory) {
    foreach ($entry in Get-ChildItem Env:) {
        if ([string]::IsNullOrEmpty($entry.Value)) { continue }
        switch -Regex ($entry.Name) {
            '^CARGO_PROFILE_.+_DEBUG$' {
                if ($entry.Value -notin @('0','false','none')) { throw 'Cargo profile debug override is enabled (value omitted)' }
                continue
            }
            '^CARGO_PROFILE_.+_INCREMENTAL$' {
                if ($entry.Value -cne 'false') { throw 'Cargo profile incremental override is enabled (value omitted)' }
                continue
            }
            '^CARGO_PROFILE_' { throw 'Unreviewed Cargo profile override (value omitted)' }
            '^CARGO_INCREMENTAL$' {
                if ($entry.Value -cne '0') { throw 'CARGO_INCREMENTAL must be zero for normal builds' }
                continue
            }
            '^CARGO_BUILD_INCREMENTAL$' {
                if ($entry.Value -cne 'false') { throw 'Cargo build incremental override is enabled (value omitted)' }
                continue
            }
            '^(RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_ENCODED_RUSTDOCFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_BUILD_RUSTDOCFLAGS|CARGO_TARGET_.+_RUSTFLAGS|CARGO_TARGET_.+_RUSTDOCFLAGS)$' {
                if ($entry.Name -cne 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS') {
                    throw 'Global, encoded or unreviewed-target Rust flags are not allowed (values omitted)'
                }
                Assert-AiwBuildFlags $entry.Value
                continue
            }
            '^(RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER)$' {
                throw 'Unexpected compiler or wrapper override (value omitted)'
            }
            '^CARGO_TARGET_.+_LINKER$' { throw 'Unexpected linker override (value omitted)' }
            '^CARGO_BUILD_TARGET_DIR$' { throw 'Use only CARGO_TARGET_DIR for the single build cache' }
            '^CARGO_BUILD_BUILD_DIR$' {
                if ($entry.Value.Contains('{')) { throw 'Unreviewed intermediate-directory template' }
                $intermediate = [IO.Path]::GetFullPath($entry.Value, $WorkingDirectory)
                Assert-AiwBuildLocalDirectory $intermediate
                if (-not (Test-AiwBuildPathWithin $intermediate $Target)) {
                    throw 'Intermediate build directory escapes the single build cache'
                }
                continue
            }
        }
    }
}

function Assert-AiwBuildCargoConfigs([string]$WorkingDirectory) {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $directory = $WorkingDirectory
    while ($directory) {
        foreach ($leaf in @('config','config.toml')) { [void]$paths.Add((Join-Path $directory ('.cargo\'+$leaf))) }
        $directory = [IO.Path]::GetDirectoryName($directory.TrimEnd('\'))
    }
    $cargoHome = if ($env:CARGO_HOME) { [IO.Path]::GetFullPath($env:CARGO_HOME, $WorkingDirectory) } else { Join-Path $env:USERPROFILE '.cargo' }
    Assert-AiwBuildLocalDirectory $cargoHome
    foreach ($leaf in @('config','config.toml')) { [void]$paths.Add((Join-Path $cargoHome $leaf)) }
    foreach ($path in $paths) {
        try { $attributes = [IO.File]::GetAttributes($path) }
        catch [IO.FileNotFoundException] { continue } catch [IO.DirectoryNotFoundException] { continue }
        Assert-AiwBuildLocalDirectory ([IO.Path]::GetDirectoryName($path))
        if (($attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Directory)) -ne 0 -or
            [IO.FileInfo]::new($path).Length -gt 65536) { throw 'Cargo configuration is redirected, non-ordinary or oversized' }
        $section = ''
        foreach ($line in [IO.File]::ReadAllLines($path, [Text.UTF8Encoding]::new($false,$true))) {
            $text = $line.Trim()
            if (-not $text -or $text.StartsWith('#')) { continue }
            if ($text -cmatch '^\[(profile\.(dev|test|release|bench)|build)\]$') { $section = $Matches[1]; continue }
            if (($section -clike 'profile.*' -and $text -cmatch '^(debug\s*=\s*(0|false|"none")|incremental\s*=\s*false)\s*(#.*)?$') -or
                ($section -ceq 'build' -and $text -cmatch '^incremental\s*=\s*false\s*(#.*)?$')) { continue }
            # A deliberately closed subset, not a partial general TOML parser.
            # Unknown registry/auth or build settings require separate review;
            # never include configuration contents or credentials in the error.
            throw 'Cargo configuration is outside the reviewed bounded subset (contents omitted)'
        }
        [pscustomobject]@{path=$path;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
    }
}

function Get-AiwBuildCacheBytes([string]$Target) {
    $total = 0L
    $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Target)
    while ($queue.Count) {
        $directory = $queue.Dequeue()
        try { $attributes = [IO.File]::GetAttributes($directory) }
        catch [IO.FileNotFoundException] { continue } catch [IO.DirectoryNotFoundException] { continue }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Build cache contains a redirect' }
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes = [IO.File]::GetAttributes($path)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Build cache contains a redirect' }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($path) }
            else { $total += [IO.FileInfo]::new($path).Length }
            if ($total -gt 8GB) { throw 'Build not started: cache exceeds the 8 GiB pre-build budget; no automatic cleanup' }
        }
    }
    return $total
}

function Get-AiwBuildAvailableBytes([string]$Target) {
    return [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Target)).AvailableFreeSpace
}

# Only the fresh per-check fixture directory, after its foreground test exits.
# Never use this for a cache, retained run, or historical temporary directory.
function Remove-AiwOwnedTestDirectory {
    param([string]$Path, [string]$Parent,
        [ValidateRange(1,100000)][int]$MaximumEntries=100000,
        [ValidateRange(1,64)][int]$MaximumDepth=64)
    $resolved = [IO.Path]::GetFullPath($Path)
    $expectedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -cne $expectedParent -or
        [IO.Path]::GetFileName($resolved) -cnotmatch '^aiwt-[0-9a-f]{12}$') {
        throw 'Unexpected owned test directory; cleanup refused'
    }
    Assert-AiwBuildLocalDirectory $resolved
    # Audit the entire tree without following redirects before recursive removal.
    # Oversized or redirected leftovers require investigation, never a bypass.
    $entries=0; $bytes=0L
    $queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($resolved)
    while ($queue.Count) {
        $directory=$queue.Dequeue()
        if (-not (Test-Path -LiteralPath $directory)) { continue }
        foreach ($entry in [IO.DirectoryInfo]::new($directory).EnumerateFileSystemInfos()) {
            $entries++
            if ($entries -gt $MaximumEntries -or
                [IO.Path]::GetRelativePath($resolved,$entry.FullName).Split('\').Count -gt $MaximumDepth) {
                throw 'Owned test directory exceeds cleanup entry/depth bounds'
            }
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Owned test directory contains a redirect' }
            if (($entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($entry.FullName) }
            else { $bytes+=$entry.Length; if ($bytes -gt 8GB) { throw 'Owned test directory exceeds cleanup byte bound' } }
        }
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction Stop }
}

function Assert-AiwBuildStoragePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RepositoryRoot, [string]$WorkingDirectory = $RepositoryRoot)
    $repo = [IO.Path]::GetFullPath($RepositoryRoot)
    $working = [IO.Path]::GetFullPath($WorkingDirectory)
    Assert-AiwBuildLocalDirectory $repo; Assert-AiwBuildLocalDirectory $working
    if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        throw 'Select one reusable CARGO_TARGET_DIR before building; no per-checkout cache is chosen automatically'
    }
    $target = [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR, $working)
    Assert-AiwBuildLocalDirectory $target
    if (Test-AiwBuildPathWithin $repo $target) { throw 'Build cache cannot be a repository ancestor or the repository itself' }
    Assert-AiwBuildOverrides $target $working
    $configFiles=@(Assert-AiwBuildCargoConfigs $working)
    $available = Get-AiwBuildAvailableBytes $target
    if ($available -lt 10GB) { throw 'Build not started: 10 GiB free required; no cleanup or retry is performed' }
    $cacheBytes = Get-AiwBuildCacheBytes $target
    if ($cacheBytes -lt 0 -or $cacheBytes -gt 8GB) {
        throw 'Build not started: cache exceeds the 8 GiB pre-build budget; no automatic cleanup'
    }
    [pscustomobject]@{targetDirectory=$target;cacheBytes=$cacheBytes;availableBytes=$available;maximumCacheBytes=8GB;minimumFreeBytes=10GB;configFiles=$configFiles}
}
