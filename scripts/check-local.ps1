#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Format', 'Provider', 'Cli', 'Platform', 'Workspace', 'Clippy', 'Msrv', 'Governance')]
    [string[]]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$logRoot = Join-Path ([IO.Path]::GetTempPath()) ('aiw-local-checks-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $logRoot | Out-Null
$results = @()
$startedAt = [DateTime]::UtcNow.ToString('o')
$head = $null
$before = @()
$after = @()
Push-Location -LiteralPath $repoRoot
try {
    $head = & git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify checkout' }
    $before = @(& git status --porcelain=v1)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read checkout status' }
    foreach ($name in ($Check | Select-Object -Unique)) {
        $program = 'cargo'
        $arguments = switch ($name) {
            Format { @('fmt', '--all', '--check') }
            Provider { @('test', '-p', 'aiw-provider-wsb', '--locked', '--offline') }
            Cli { @('test', '-p', 'aiw-cli', '--locked', '--offline') }
            Platform { @('test', '-p', 'aiw-windows-platform', '--locked', '--offline') }
            Workspace { @('test', '--workspace', '--locked', '--offline') }
            Clippy { @('clippy', '--workspace', '--all-targets', '--locked', '--offline', '--', '-D', 'warnings') }
            Msrv { @('+1.85.0', 'check', '--workspace', '--all-targets', '--locked', '--offline') }
            Governance {
                $program = 'pwsh'
                @('-NoProfile', '-NonInteractive', '-File', (Join-Path $PSScriptRoot 'verify.ps1'), '-GovernanceOnly')
            }
        }
        $stdout = Join-Path $logRoot "$name.stdout.log"
        $stderr = Join-Path $logRoot "$name.stderr.log"
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $exitCode = $null
        $failure = $null
        $previousTemp = $env:TEMP
        $previousTmp = $env:TMP
        $testTemp = $null
        try {
            if ($program -eq 'cargo' -and $arguments[0] -eq 'test') {
                # Native parent-entry checks are bounded. Unrelated files in a
                # long-lived user TEMP must not determine whether fixtures work.
                # Keep the fixture root short for Win32 APIs without long-path prefixes.
                $testTemp = Join-Path ([IO.Path]::GetTempPath()) ('aiwt-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
                New-Item -ItemType Directory -Path $testTemp | Out-Null
                $env:TEMP = $testTemp
                $env:TMP = $testTemp
            }
            & $program @arguments 1> $stdout 2> $stderr
            $exitCode = $LASTEXITCODE
        } catch { $failure = $_.Exception.Message }
        finally {
            $env:TEMP = $previousTemp
            $env:TMP = $previousTmp
        }
        $timer.Stop()
        $record = [ordered]@{
            check = $name
            program = $program
            arguments = $arguments
            passed = $null -eq $failure -and $exitCode -eq 0
            exitCode = $exitCode
            seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 2)
            stdout = $stdout
            stderr = $stderr
            testTemp = $testTemp
        }
        if (!$record.passed) {
            $record.failure = $failure
            $record.tail = @(foreach ($path in @($stderr, $stdout)) {
                if (Test-Path -LiteralPath $path) {
                    Get-Content -LiteralPath $path -Tail 8 | ForEach-Object { $_.Substring(0, [Math]::Min(300, $_.Length)) }
                }
            })
        }
        $results += $record
        # Persist each result so an interrupted later check does not lose earlier logs.
        ConvertTo-Json -InputObject $results -Depth 5 | Set-Content -LiteralPath (Join-Path $logRoot 'checks.json')
        if (!$record.passed) { break }
    }
    $after = @(& git status --porcelain=v1)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read final checkout status' }
} finally { Pop-Location }
$summary = [ordered]@{
    root = $repoRoot
    head = $head
    startedAtUtc = $startedAt
    finishedAtUtc = [DateTime]::UtcNow.ToString('o')
    statusBefore = $before
    statusAfter = $after
    # Status is diagnostic only, not a content fingerprint or a reusable validation cache.
    requested = $Check
    passed = @($results | Where-Object { !$_.passed }).Count -eq 0
    checks = $results
    logs = $logRoot
}
$json = $summary | ConvertTo-Json -Depth 6
$json | Set-Content -LiteralPath (Join-Path $logRoot 'summary.json')
[ordered]@{
    root = $repoRoot
    head = $head
    passed = $summary.passed
    changedEntriesBefore = $before.Count
    changedEntriesAfter = $after.Count
    checks = @($results | ForEach-Object {
        $brief = [ordered]@{ check = $_.check; passed = $_.passed; exitCode = $_.exitCode; seconds = $_.seconds }
        if (!$_.passed) { $brief.failure = $_.failure; $brief.tail = $_.tail }
        $brief
    })
    logs = $logRoot
} | ConvertTo-Json -Depth 5
if (!$summary.passed) { exit 1 }
