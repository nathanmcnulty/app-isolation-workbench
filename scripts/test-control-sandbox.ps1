#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][switch]$RunDisposableControls)
$ErrorActionPreference='Stop'
if (!$RunDisposableControls) { throw 'Explicit disposable-control opt-in required' }
$repo=Split-Path -Parent $PSScriptRoot
$binary=Join-Path $repo 'target\control-static\x86_64-pc-windows-msvc\debug\aiw-control-fixture.exe'
$provider='C:\Program Files\WindowsApps\MicrosoftWindows.WindowsSandbox_0.8.107.0_x64__cw5n1h2txyewy\wsb.exe'
if ((Get-FileHash -LiteralPath $provider).Hash.ToLowerInvariant() -ne '247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441') { throw 'Reviewed Sandbox provider changed' }
function Invoke-Provider([string[]]$Arguments, [switch]$Discard) {
    $info=[Diagnostics.ProcessStartInfo]::new($provider)
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=!$Discard; $info.RedirectStandardError=!$Discard
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process=[Diagnostics.Process]::Start($info)
    try {
        if (!$Discard) { $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync() }
        if (!$process.WaitForExit(60000)) { $process.Kill(); throw 'Provider deadline exceeded' }
        if ($process.ExitCode -ne 0) { throw "Provider exited $($process.ExitCode)" }
        if (!$Discard) {
            if (!$stdout.Wait(5000) -or !$stderr.Wait(5000)) { throw 'Provider stream deadline exceeded' }
            if ($stdout.Result.Length -gt 65536 -or $stderr.Result.Length -gt 65536) { throw 'Provider output exceeded bounds' }
            $stdout.Result
        }
    } finally { $process.Dispose() }
}
$root=Join-Path $env:TEMP ('aiw-control-baseline-'+[guid]::NewGuid())
New-Item -ItemType Directory -Path $root | Out-Null
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $root /inheritance:r /grant:r "*${owner}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Host workspace ACL failed' }
Write-Output "CONTROL_ROOT=$root"
for ($iteration=1; $iteration -le 2; $iteration++) {
    $initial=Invoke-Provider @('list','--raw') | ConvertFrom-Json
    if (@($initial.WindowsSandboxEnvironments).Count -ne 0) { throw 'Existing Sandbox; refusing control start' }
    $trial=New-Item -ItemType Directory (Join-Path $root "trial-$iteration")
    $inputDirectory=New-Item -ItemType Directory (Join-Path $trial 'input')
    $outputDirectory=New-Item -ItemType Directory (Join-Path $trial 'output')
    Copy-Item -LiteralPath $binary -Destination (Join-Path $inputDirectory 'aiw-control-fixture.exe')
    Copy-Item -LiteralPath (Join-Path $repo 'fixtures\control\guest-baseline.ps1') -Destination (Join-Path $inputDirectory 'guest.ps1')
    $hash=(Get-FileHash -LiteralPath (Join-Path $inputDirectory 'aiw-control-fixture.exe')).Hash.ToLowerInvariant()
    Set-Content -LiteralPath (Join-Path $inputDirectory 'fixture.sha256') -Value $hash
    $held=@(Get-ChildItem -LiteralPath $inputDirectory -File | ForEach-Object { [IO.File]::Open($_.FullName,'Open','Read','Read') })
    $id=[guid]::NewGuid().ToString()
    $inputXml=[Security.SecurityElement]::Escape($inputDirectory.FullName)
    $outputXml=[Security.SecurityElement]::Escape($outputDirectory.FullName)
    $config="<Configuration><vGPU>Disable</vGPU><Networking>Disable</Networking><AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><ProtectedClient>Enable</ProtectedClient><PrinterRedirection>Disable</PrinterRedirection><ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>2048</MemoryInMB><MappedFolders><MappedFolder><HostFolder>$inputXml</HostFolder><SandboxFolder>C:\AIW\Input</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder><MappedFolder><HostFolder>$outputXml</HostFolder><SandboxFolder>C:\AIW\Output</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\AIW\Input\guest.ps1</Command></LogonCommand></Configuration>"
    $journal=[ordered]@{schemaVersion='aiw.dev/research/control-host/v0alpha1'; productionEvidence=$false; sandboxId=$id; fixtureSha256=$hash; guestScriptSha256=(Get-FileHash (Join-Path $inputDirectory 'guest.ps1')).Hash.ToLowerInvariant(); configSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($config))).ToLowerInvariant(); cleanupVerified=$false}
    $journal | ConvertTo-Json | Set-Content (Join-Path $trial 'host-journal.json')
    [IO.File]::WriteAllText((Join-Path $trial 'configuration.wsb'),$config)
    $journal.providerSha256=(Get-FileHash -LiteralPath $provider).Hash.ToLowerInvariant()
    if ($journal.providerSha256 -ne '247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441') { throw 'Provider changed before start' }
    $journal.workspaceRoot=$trial.FullName
    $journal | ConvertTo-Json | Set-Content (Join-Path $trial 'host-journal.json')
    try {
        $started=Invoke-Provider @('start','--raw','--id',$id,'--config',$config) | ConvertFrom-Json
        if ($started.Id -ne $id) { throw 'Start session identity mismatch' }
        $sessions=Invoke-Provider @('list','--raw') | ConvertFrom-Json
        if (@($sessions.WindowsSandboxEnvironments).Count -ne 1 -or $sessions.WindowsSandboxEnvironments[0].Id -ne $id) { throw 'Session identity mismatch' }
        Invoke-Provider @('connect','--raw','--id',$id) -Discard
        $deadline=[DateTime]::UtcNow.AddSeconds(180)
        while (!(Test-Path (Join-Path $outputDirectory 'control-result.json'))) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Control guest deadline exceeded' }
            Start-Sleep -Seconds 2
        }
    } finally {
        try {
            Invoke-Provider @('stop','--raw','--id',$id) | Out-Null
            $remaining=Invoke-Provider @('list','--raw') | ConvertFrom-Json
            $journal.cleanupVerified=@($remaining.WindowsSandboxEnvironments | Where-Object Id -eq $id).Count -eq 0
            $journal | ConvertTo-Json | Set-Content (Join-Path $trial 'host-journal.json')
        } finally { foreach ($handle in $held) { $handle.Dispose() } }
    }
    if (!$journal.cleanupVerified) { throw 'Exact control session cleanup unverified' }
    $resultPath=Join-Path $outputDirectory 'control-result.json'
    if ((Get-Item -LiteralPath $resultPath).Length -gt 65536) { throw 'Control result exceeded bounds' }
    $journal.resultSha256=(Get-FileHash -LiteralPath $resultPath).Hash.ToLowerInvariant()
    $journal | ConvertTo-Json | Set-Content (Join-Path $trial 'host-journal.json')
    $result=Get-Content $resultPath -Raw | ConvertFrom-Json
    if ($result.error -or $result.stage -ne 'finished') { throw "Guest control failed: $($result.error)" }
    Write-Output "CONTROL_TRIAL_$iteration=$($result.stage)"
}
& (Join-Path $repo 'fixtures\control\verify-baseline.ps1') -Root $root | Set-Content (Join-Path $root 'repeatability.json')
$report=Get-Content (Join-Path $root 'repeatability.json') -Raw | ConvertFrom-Json
$markdown=@('# Repeated execution controls','','Two fresh Windows Sandbox trials produced matching control results and recorded exact-session cleanup. These are development controls, not approved application evidence or an AppContainer verdict.','','| Case | Observation | Canary outcome | Exit | Integrity | Elevated |','|---|---|---|---|---|---|')
foreach ($case in $report.normalized.cases) { $markdown += "| $($case.case) | $($case.status) | $($case.readOutcome) | $($case.exitCode) | $($case.integrity) | $($case.elevated) |" }
$markdown += @('','The denied read is an ACL negative control. Missing files remain distinct. Child token/PID/SID bindings and fixed document/canary hashes were checked. Per-run configuration hashes and normalized provider/environment commitments are retained in the JSON report.')
$markdown | Set-Content (Join-Path $root 'repeatability.md')
Write-Output "CONTROL_REPORT=$root\repeatability.json"
