#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision,
    [Parameter(Mandatory)][string]$ReportDirectory
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64'){throw 'Stable x64 PowerShell Core >=7.6 required'}
$repo=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'build-storage.ps1')
function Assert-Source {
    if ((& git -C $repo rev-parse HEAD).Trim() -cne $SourceRevision -or $LASTEXITCODE -ne 0) { throw 'Source revision differs' }
    $status=@(& git -C $repo status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $status.Count) { throw 'Exact clean source required' }
}
function Measure-Cache([string]$Path,[switch]$AllowTransientIO) {
    $bytes=0L;$files=0L;$incomplete=0
    if (Test-Path -LiteralPath $Path) {
        $queue=[Collections.Generic.Queue[string]]::new();$queue.Enqueue($Path)
        while($queue.Count) {
            try {
                $directory=$queue.Dequeue();$attributes=[IO.File]::GetAttributes($directory)
                if($attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Build cache contains a reparse point'}
                foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
                    try {
                        $attributes=[IO.File]::GetAttributes($entry)
                        if($attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Build cache contains a reparse point'}
                        if($attributes -band [IO.FileAttributes]::Directory){$queue.Enqueue($entry)}else{$bytes+=([IO.FileInfo]::new($entry)).Length;$files++}
                    } catch [IO.FileNotFoundException] { } catch [IO.DirectoryNotFoundException] { }
                    catch [UnauthorizedAccessException] {if(-not $AllowTransientIO){throw};$incomplete++}
                }
            } catch [IO.FileNotFoundException] { } catch [IO.DirectoryNotFoundException] { }
            catch [UnauthorizedAccessException] {if(-not $AllowTransientIO){throw};$incomplete++}
        }
    }
    [ordered]@{bytes=$bytes;files=$files;freeBytes=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path)).AvailableFreeSpace;incompleteEntriesDuringSample=$incomplete}
}
function Source-Digest {
    $names=@(& git -C $repo ls-files)
    if($LASTEXITCODE -ne 0){throw 'Tracked source inventory failed'}
    $rows=@(foreach($name in $names){if($name.StartsWith('"')){throw 'Unsupported quoted source path'};$path=Join-Path $repo $name;[ordered]@{path=$name;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}})
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($rows|ConvertTo-Json -Compress)))).ToLowerInvariant()
}
function Inspect-CompilerLog([string]$Path) {
    $commands=@(Get-Content -LiteralPath $Path | Where-Object {$_ -match '\bRunning\b.*\s--crate-name\s'})
    foreach($command in $commands) {
        $command=$command.TrimEnd('`','"')
        if($command -match '(?:^|\s)-g(?:\s|$)' -or $command -match '-C\s*incremental(?:=|\s)' -or $command -match '-C\s*debuginfo(?:=|\s)(?!0(?:\s|$)|none(?:\s|$))[^\s]+'){throw 'Effective compiler arguments enable incremental output or debug information'}
    }
    [ordered]@{rustcInvocations=$commands.Count;compilerArgumentsObserved=($commands.Count -gt 0);crateNames=@($commands|ForEach-Object{if($_ -match '--crate-name\s+(\S+)'){$Matches[1]}}|Sort-Object -Unique);sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
}
Assert-Source
$policy=Assert-AiwBuildStoragePolicy -RepositoryRoot $repo
$sourceDigest=Source-Digest
Push-Location -LiteralPath $repo
try {
    $rustcIdentity=@(& rustc -vV);if($LASTEXITCODE -ne 0){throw 'rustc identity unavailable'}
    $cargoIdentity=@(& cargo -vV);if($LASTEXITCODE -ne 0){throw 'Cargo identity unavailable'}
    $compilerPath=(& rustup which rustc).Trim();if($LASTEXITCODE -ne 0){throw 'Selected compiler unavailable'}
} finally {Pop-Location}
$compilerHash=(Get-FileHash -LiteralPath $compilerPath).Hash.ToLowerInvariant()
$overrideNames=@(Get-ChildItem Env:|Where-Object{$_.Name -match '^(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_INCREMENTAL|CARGO_PROFILE_.*|RUSTC_.*WRAPPER|CARGO_.*RUSTFLAGS|CARGO_BUILD_BUILD_DIR)$'}|Select-Object -ExpandProperty Name)
$report=[IO.Path]::GetFullPath($ReportDirectory)
if($report.Equals($policy.targetDirectory,[StringComparison]::OrdinalIgnoreCase) -or $report.Equals($repo,[StringComparison]::OrdinalIgnoreCase) -or $report.StartsWith($policy.targetDirectory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or $report.StartsWith($repo.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Reports must be outside source and build cache'}
if(Test-Path -LiteralPath $report){throw 'Fresh small report directory required; reuse the build directory, not execution evidence'}
$null=[IO.Directory]::CreateDirectory($report)
$oldTarget=$env:CARGO_TARGET_DIR;$oldFlags=$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS
$passes=[Collections.Generic.List[object]]::new();$failure=$null;$artifacts=@();$before=Measure-Cache $policy.targetDirectory
$arguments=@('build','--locked','--offline','--color','never','-vv','--target','x86_64-pc-windows-msvc','-p','aiw-cli','-p','aiw-guest-agent','-p','aiw-control-fixture')
Push-Location -LiteralPath $repo
try {
    $env:CARGO_TARGET_DIR=$policy.targetDirectory
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS='-C target-feature=+crt-static'
    # The first two builds measure the normal dev path. Refresh the reviewed
    # release tools afterward in the existing release slot of this same cache.
    for($pass=1;$pass -le 3;$pass++) {
        $null=Assert-AiwBuildStoragePolicy -RepositoryRoot $repo
        Assert-Source
        $stdout=Join-Path $report "build-$pass.stdout.log";$stderr=Join-Path $report "build-$pass.stderr.log"
        $timer=[Diagnostics.Stopwatch]::StartNew()
        $cargoPath=(Get-Command cargo -CommandType Application).Source
        $passArguments=if($pass -eq 3){$arguments+@('--release')}else{$arguments}
        $entry=[ordered]@{pass=$pass;profile=if($pass -eq 3){'release'}else{'dev'};arguments=$passArguments;started=$false;rootProcessId=$null;rootBirthUtc=$null;rootExitObserved=$false;exitCode=$null;killRequested=$false;primaryError=$null;cleanupError=$null;seconds=$null;cache=$null;peakSampledCacheBytes=$before.bytes;incompleteSamplingEvents=0;compiler=$null;artifacts=@()}
        $passes.Add($entry);$process=$null
        # Start-Process owns redirection handles; the held process object is the
        # only root this watchdog may terminate, including its build children.
        try {
            $process=Start-Process -FilePath $cargoPath -ArgumentList $passArguments -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            $null=$process.Handle
            $entry.started=$true;$entry.rootProcessId=$process.Id;$entry.rootBirthUtc=$process.StartTime.ToUniversalTime().ToString('o')
            [IO.File]::WriteAllText((Join-Path $report "build-$pass-start.json"),($entry|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
            while(-not $process.WaitForExit(5000)) {
                $sample=Measure-Cache $policy.targetDirectory -AllowTransientIO
                $entry.incompleteSamplingEvents+=$sample.incompleteEntriesDuringSample
                $entry.peakSampledCacheBytes=[Math]::Max($entry.peakSampledCacheBytes,$sample.bytes)
                if($sample.bytes -gt $policy.maximumCacheBytes -or $sample.freeBytes -lt 2GB -or $timer.Elapsed.TotalMinutes -gt 20 -or ([IO.FileInfo]::new($stdout)).Length -gt 8MB -or ([IO.FileInfo]::new($stderr)).Length -gt 8MB){throw 'Owned build exceeded cache, free-space, time or diagnostic budget'}
            }
            $entry.rootExitObserved=$true;$entry.exitCode=$process.ExitCode
            $after=Measure-Cache $policy.targetDirectory;$entry.cache=$after
            $entry.peakSampledCacheBytes=[Math]::Max($entry.peakSampledCacheBytes,$after.bytes)
            if($after.bytes -gt $policy.maximumCacheBytes -or $after.freeBytes -lt 2GB -or $timer.Elapsed.TotalMinutes -gt 20 -or ([IO.FileInfo]::new($stdout)).Length -gt 8MB -or ([IO.FileInfo]::new($stderr)).Length -gt 8MB){throw 'Completed build exceeded storage, time or diagnostic budget'}
            $entry.compiler=Inspect-CompilerLog $stderr
            if($entry.exitCode -eq 0){
                $leaf=if($pass -eq 3){'release'}else{'debug'}
                foreach($name in @('aiw.exe','aiw-guest-agent.exe','aiw-control-fixture.exe')){
                    $path=Join-Path $policy.targetDirectory ("x86_64-pc-windows-msvc\$leaf\"+$name)
                    # Since Rust 1.79, MSVC may retain backtrace-symbol PDBs
                    # with debuginfo=0/strip=debuginfo. Measure, don't infer flags.
                    $pdb=Join-Path ([IO.Path]::GetDirectoryName($path)) ([IO.Path]::GetFileNameWithoutExtension($name).Replace('-','_')+'.pdb')
                    $pdbBytes=if(Test-Path -LiteralPath $pdb){([IO.FileInfo]::new($pdb)).Length}else{0L}
                    $entry.artifacts+=,[ordered]@{name=$name;sizeBytes=([IO.FileInfo]::new($path)).Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();pdbBytes=$pdbBytes}
                }
            }
        } catch {$entry.primaryError=$_.Exception.Message}
        finally {
            if($process){
                try {if(-not $process.HasExited){$entry.killRequested=$true;$process.Kill($true);if(-not $process.WaitForExit(30000)){throw 'Owned build root exit is unconfirmed'}};$entry.rootExitObserved=$process.HasExited;if($entry.rootExitObserved){$entry.exitCode=$process.ExitCode}}
                catch {$entry.cleanupError=$_.Exception.Message}
                finally {$process.Dispose()}
            }
            $timer.Stop();$entry.seconds=$timer.Elapsed.TotalSeconds
            try{$entry.cache=Measure-Cache $policy.targetDirectory}catch{if(-not $entry.cleanupError){$entry.cleanupError=$_.Exception.Message}}
        }
        if($entry.primaryError -or $entry.cleanupError -or -not $entry.rootExitObserved -or $entry.exitCode -ne 0){throw "Build $pass failed; original facts and logs retained"}
        $compiler=$entry.compiler
        # A warm cache is valid and must not force cleanup/recompilation merely
        # to manufacture a compiler trace. Zero commands mean flags were not
        # observed in this pass; retained cold-build evidence is separate.
        if($pass -eq 2 -and $compiler.rustcInvocations -ne 0){throw 'Identical second build unexpectedly recompiled; inspect retained logs'}
        if($pass -eq 2 -and ($entry.artifacts|ConvertTo-Json -Compress) -cne ($passes[0].artifacts|ConvertTo-Json -Compress)){throw 'Identical second build changed first-party artifacts'}
        Assert-Source
    }
    $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs=(& $vswhere -latest -products * -property installationPath).Trim();if($LASTEXITCODE -ne 0){throw 'PE inspector discovery failed'}
    $dumpbin=Get-ChildItem -LiteralPath (Join-Path $vs 'VC\Tools\MSVC') -Filter dumpbin.exe -Recurse -File|Sort-Object FullName -Descending|Select-Object -First 1 -ExpandProperty FullName
    if(-not $dumpbin){throw 'PE inspector unavailable'}
    foreach($name in @('aiw.exe','aiw-guest-agent.exe','aiw-control-fixture.exe')) {
        $path=Join-Path $policy.targetDirectory ('x86_64-pc-windows-msvc\release\'+$name)
        $headers=@(& $dumpbin /headers $path);if($LASTEXITCODE -ne 0 -or ($headers -join "`n") -notmatch '(?m)^\s+8664 machine \(x64\)'){throw 'First-party artifact is not AMD64 PE'}
        $imports=@(& $dumpbin /dependents $path);if($LASTEXITCODE -ne 0 -or ($imports -join "`n") -match '(?im)^\s+((?:VCRUNTIME|MSVCP|MSVCR)[^\s]*\.dll|UCRTBASE\.dll|api-ms-win-crt-[^\s]+\.dll)\s*$'){throw 'First-party artifact imports dynamic Visual C++ runtime'}
        [IO.File]::WriteAllText((Join-Path $report ($name+'.pe.txt')),(($headers+$imports) -join "`n"),[Text.UTF8Encoding]::new($false))
        $artifacts+=,[ordered]@{name=$name;path=$path;sizeBytes=([IO.FileInfo]::new($path)).Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();machine='amd64';crt='static'}
    }
    if((Source-Digest) -cne $sourceDigest){throw 'Tracked source bytes changed during builds'}
} catch {$failure=$_.Exception.Message;throw}
finally {
    [Environment]::SetEnvironmentVariable('CARGO_TARGET_DIR',$oldTarget,'Process')
    [Environment]::SetEnvironmentVariable('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS',$oldFlags,'Process')
    Pop-Location
    $result=[ordered]@{schemaVersion='aiw.dev/assessment-tool-build-measurement/v0alpha1';sourceRevision=$SourceRevision;sourceDigestSha256=$sourceDigest;rustc=$rustcIdentity;cargo=$cargoIdentity;compilerPath=$compilerPath;compilerSha256=$compilerHash;inheritedOverrideNames=$overrideNames;targetDirectory=$policy.targetDirectory;normalBuildPasses=2;artifactProfile='release';target='x86_64-pc-windows-msvc';arguments=$arguments;policy=$policy;before=$before;passes=$passes;artifacts=$artifacts;failure=$failure;applicationExecutions=0;providerCalls=0;cacheCleanupPerformed=$false;scope='Two normal core dev builds followed by release-artifact refresh in the same cache. CLI, guest agent and first-party control only; separate desktop workspace not built'}
    [IO.File]::WriteAllText((Join-Path $report 'measurement.json'),($result|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
}
$result|ConvertTo-Json -Depth 15
