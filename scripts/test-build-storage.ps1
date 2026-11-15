#Requires -Version 7.6
#Requires -PSEdition Core
# Pester-free, inert policy tests. No Cargo, cache cleanup or compiler calls.
# Small fixtures created by this invocation are removed after environment restore.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'build-storage.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('aiw-build-policy-' + [guid]::NewGuid().ToString('N'))
$repo = Join-Path $root 'repo'; $cargoHome = Join-Path $root 'cargo-home'
[void][IO.Directory]::CreateDirectory($repo); [void][IO.Directory]::CreateDirectory($cargoHome)
$saved = @{}
$pattern = '^(CARGO_(PROFILE|INCREMENTAL|BUILD|TARGET|ENCODED|HOME)|RUSTFLAGS$|RUSTDOCFLAGS$|RUSTC($|_))'
foreach ($item in Get-ChildItem Env: | Where-Object Name -Match $pattern) { $saved[$item.Name] = $item.Value }
$originalFree = ${function:Get-AiwBuildAvailableBytes}
$originalCache = ${function:Get-AiwBuildCacheBytes}
$script:freeBytes = 12GB; $script:passed = 0
function Get-AiwBuildAvailableBytes([string]$Target) { return $script:freeBytes }
function Assert-Case([bool]$Value) { if (-not $Value) { throw 'Build policy assertion failed' }; $script:passed++ }
function Refuses([scriptblock]$Operation) {
    try { & $Operation | Out-Null } catch {
        if ($_.Exception.Message.Contains('DO_NOT_LOG')) { throw 'Policy exposed override contents' }
        $script:passed++; return
    }
    throw 'Policy unexpectedly accepted an unsafe case'
}
try {
    foreach ($item in Get-ChildItem Env: | Where-Object Name -Match $pattern) { Remove-Item -LiteralPath ('Env:'+$item.Name) }
    $env:CARGO_HOME = $cargoHome
    $policy = Assert-AiwBuildStoragePolicy -RepositoryRoot $repo
    Assert-Case ($policy.targetDirectory -ceq (Join-Path $repo 'target'))
    Assert-Case ($policy.cacheBytes -eq 0 -and -not (Test-Path -LiteralPath $policy.targetDirectory))
    $env:CARGO_TARGET_DIR = 'cache'
    $policy = Assert-AiwBuildStoragePolicy -RepositoryRoot $repo -WorkingDirectory $repo
    Assert-Case ($policy.targetDirectory -ceq (Join-Path $repo 'cache'))
    Assert-Case (-not (Test-Path -LiteralPath $policy.targetDirectory))
    [void][IO.Directory]::CreateDirectory($policy.targetDirectory)
    [IO.File]::WriteAllBytes((Join-Path $policy.targetDirectory 'inert.bin'), [byte[]]@(1,2,3))
    Assert-Case ((Assert-AiwBuildStoragePolicy -RepositoryRoot $repo).cacheBytes -eq 3)
    $script:freeBytes = 10GB - 1
    Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
    $script:freeBytes = 10GB
    Assert-Case ((Assert-AiwBuildStoragePolicy -RepositoryRoot $repo).availableBytes -eq 10GB)
    function Get-AiwBuildCacheBytes([string]$Target) { return 8GB + 1 }
    # The public policy must enforce the returned budget, not rely only on the
    # traversal helper throwing early; no multi-GiB fixture is ever allocated.
    Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
    Set-Item Function:Get-AiwBuildCacheBytes $originalCache
    foreach ($case in @(
        @('CARGO_INCREMENTAL','1'), @('CARGO_PROFILE_DEV_DEBUG','2'),
        @('CARGO_PROFILE_TEST_INCREMENTAL','true'), @('CARGO_PROFILE_RELEASE_DEBUG','1'),
        @('CARGO_PROFILE_DEV_OPT_LEVEL','3'), @('RUSTFLAGS','-C debuginfo=2'),
        @('RUSTFLAGS','-C target-feature=+crt-static'),
        @('CARGO_BUILD_RUSTFLAGS','-C target-feature=+crt-static'),
        @('CARGO_ENCODED_RUSTFLAGS',('-C'+[char]31+'incremental=DO_NOT_LOG')),
        @('CARGO_ENCODED_RUSTFLAGS',('-C'+[char]31+'target-feature=+crt-static')),
        @('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS','-C target-feature=+crt-static -Cdebuginfo=2'),
        @('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS','-C target-feature=+crt-static -C target-feature=+crt-static'),
        @('RUSTC_WRAPPER','C:\DO_NOT_LOG.exe'), @('RUSTC_WORKSPACE_WRAPPER','C:\DO_NOT_LOG.exe'),
        @('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER','C:\DO_NOT_LOG.exe'),
        @('CARGO_BUILD_TARGET_DIR','C:\DO_NOT_LOG'), @('CARGO_BUILD_BUILD_DIR',(Join-Path $root 'outside'))
    )) {
        Set-Item -LiteralPath ('Env:'+$case[0]) -Value $case[1]
        Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
        Remove-Item -LiteralPath ('Env:'+$case[0])
    }
    $env:CARGO_INCREMENTAL='0'; $env:CARGO_PROFILE_DEV_DEBUG='0'; $env:CARGO_PROFILE_TEST_INCREMENTAL='false'
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS='-C target-feature=+crt-static'
    $env:CARGO_BUILD_BUILD_DIR=Join-Path $policy.targetDirectory 'intermediate'
    Assert-Case ((Assert-AiwBuildStoragePolicy -RepositoryRoot $repo).cacheBytes -eq 3)
    foreach ($name in @('CARGO_INCREMENTAL','CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_INCREMENTAL','CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS','CARGO_BUILD_BUILD_DIR')) { Remove-Item -LiteralPath ('Env:'+$name) }
    $configRoot=Join-Path $repo '.cargo'; [void][IO.Directory]::CreateDirectory($configRoot)
    $config=Join-Path $configRoot 'config.toml'
    [IO.File]::WriteAllText($config, "[profile.dev]`ndebug=0`nincremental=false`n")
    Assert-Case ((Assert-AiwBuildStoragePolicy -RepositoryRoot $repo).cacheBytes -eq 3)
    foreach ($text in @("[profile.dev]`ndebug=2", "[build]`nincremental=true", "[build]`ntarget-dir='DO_NOT_LOG'", "[registries.private]`ntoken='DO_NOT_LOG'")) {
        [IO.File]::WriteAllText($config,$text)
        Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
    }
    [IO.File]::WriteAllText($config,'# inert configuration')
    Refuses { Assert-AiwBuildLocalDirectory '\\server\share\cache' }
    Refuses { Assert-AiwBuildLocalDirectory 'C:\cache:stream' }
    $env:CARGO_TARGET_DIR=$repo
    Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
    $env:CARGO_TARGET_DIR=Join-Path $repo 'cache'
    $outside=Join-Path $root 'owned-link-target'; [void][IO.Directory]::CreateDirectory($outside)
    $link=Join-Path $policy.targetDirectory 'redirect'
    New-Item -ItemType Junction -Path $link -Target $outside | Out-Null
    Refuses { Assert-AiwBuildStoragePolicy -RepositoryRoot $repo }
    $result=[ordered]@{passed=$script:passed;fixtureRoot=$root;cargoInvocations=0;builds=0;freeSpaceStubbed=$true;largeCacheFixtureAllocated=$false;scope='Inert owned temporary files, config/environment cases and owned junction'}
} finally {
    foreach ($item in Get-ChildItem Env: | Where-Object Name -Match $pattern) { Remove-Item -LiteralPath ('Env:'+$item.Name) }
    foreach ($name in $saved.Keys) { Set-Item -LiteralPath ('Env:'+$name) -Value $saved[$name] }
    Set-Item Function:Get-AiwBuildAvailableBytes $originalFree
    Set-Item Function:Get-AiwBuildCacheBytes $originalCache
    # Only this freshly created fixture tree is disposable. Never clean a cache.
    if([IO.Path]::GetDirectoryName($root).TrimEnd('\') -cne ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())).TrimEnd('\') -or [IO.Path]::GetFileName($root) -cnotmatch '^aiw-build-policy-[0-9a-f]{32}$'){throw 'Unexpected test fixture root'}
    if(Test-Path -LiteralPath (Join-Path $root 'repo\cache\redirect')){Remove-Item -LiteralPath (Join-Path $root 'repo\cache\redirect') -Force}
    if(@(Get-ChildItem -LiteralPath $root -Force -Recurse -Attributes ReparsePoint).Count){throw 'Unexpected redirect in owned test fixture'}
    Remove-Item -LiteralPath $root -Recurse -Force
}
$result.fixturesRemoved=-not (Test-Path -LiteralPath $root)
$result|ConvertTo-Json -Compress
