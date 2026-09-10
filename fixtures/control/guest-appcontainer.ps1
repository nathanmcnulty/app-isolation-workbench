# Fixed research launcher, only inside a disposable Windows Sandbox worker.
$ErrorActionPreference='Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or !(Test-Path 'C:\AIW\Input\aiw-control-appcontainer.exe')) { throw 'Disposable guest required' }
$result=[ordered]@{schemaVersion='aiw.dev/research/control-appcontainer-guest/v0alpha1'; productionEvidence=$false; stage='setup'; error=$null; windowsBuild=[Environment]::OSVersion.Version.ToString()}
try {
    $fixtureHash=(Get-Content 'C:\AIW\Input\fixture.sha256' -Raw).Trim()
    $launcherHash=(Get-Content 'C:\AIW\Input\launcher.sha256' -Raw).Trim()
    foreach ($entry in @(@('aiw-control-fixture.exe',$fixtureHash),@('aiw-control-appcontainer.exe',$launcherHash))) {
        if ((Get-FileHash -LiteralPath ('C:\AIW\Input\'+$entry[0])).Hash.ToLowerInvariant() -ne $entry[1]) { throw 'Control input identity changed' }
    }
    $result.fixtureSha256=$fixtureHash
    $result.launcherSha256=$launcherHash
    $password=ConvertTo-SecureString ([guid]::NewGuid().ToString()+'aA1!') -AsPlainText -Force
    $user=New-LocalUser -Name 'AiwControlUser' -Password $password -AccountNeverExpires
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user.Name
    $result.standardUserSid=$user.SID.Value
    $credential=[pscredential]::new('.\AiwControlUser',$password)
    New-Item -ItemType Directory 'C:\AIW\Control' | Out-Null
    foreach ($name in @('aiw-control-fixture.exe','aiw-control-appcontainer.exe')) { Copy-Item -LiteralPath ('C:\AIW\Input\'+$name) -Destination ('C:\AIW\Control\'+$name) }
    & icacls.exe 'C:\AIW\Control' /grant 'AiwControlUser:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Control directory ACL failed' }
    New-Item -ItemType Directory 'C:\AIW\Control\AppContainerChild' | Out-Null
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /inheritance:r /grant:r 'AiwControlUser:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory ACL failed' }
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /setowner 'AiwControlUser' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory ownership failed' }
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /setintegritylevel '(OI)(CI)L' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory integrity label failed' }
    $result.stage='paired-controls'
    $process=Start-Process -FilePath 'C:\AIW\Control\aiw-control-appcontainer.exe' -WorkingDirectory 'C:\AIW\Control' -Credential $credential -LoadUserProfile -RedirectStandardOutput 'C:\AIW\Control\launcher.json' -RedirectStandardError 'C:\AIW\Control\launcher.stderr' -WindowStyle Hidden -PassThru
    $null=$process.Handle
    try {
        $result.launcherProcessId=$process.Id
        if (!$process.WaitForExit(90000)) { $process.Kill(); $process.WaitForExit(5000) | Out-Null; throw 'AppContainer control deadline exceeded' }
        $result.launcherExitCode=$process.ExitCode
        if ((Get-Item 'C:\AIW\Control\launcher.json').Length -gt 49152 -or (Get-Item 'C:\AIW\Control\launcher.stderr').Length -gt 16384) { throw 'Launcher output exceeded bounds' }
        $result.observation=Get-Content 'C:\AIW\Control\launcher.json' -Raw | ConvertFrom-Json
        if ($process.ExitCode -ne 0) { throw "Launcher failed with exit $($process.ExitCode)" }
    } finally { $process.Dispose() }
    foreach ($entry in @(@('aiw-control-fixture.exe',$fixtureHash),@('aiw-control-appcontainer.exe',$launcherHash))) {
        if ((Get-FileHash -LiteralPath ('C:\AIW\Control\'+$entry[0])).Hash.ToLowerInvariant() -ne $entry[1]) { throw 'Control executable changed during trial' }
    }
    $result.stage='finished'
} catch { $result.error=$_.Exception.Message }
$result | ConvertTo-Json -Depth 24 | Set-Content -Encoding UTF8 'C:\AIW\Output\control-result.pending.json'
Move-Item -LiteralPath 'C:\AIW\Output\control-result.pending.json' -Destination 'C:\AIW\Output\control-result.json'
