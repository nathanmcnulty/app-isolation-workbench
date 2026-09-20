# Fixed disposable-worker driver. Not a production guest-agent request or assessment receipt.
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or !(Test-Path 'C:\AIW\Input\aiw-control-fixture.exe')) { throw 'Disposable guest required' }
$result = [ordered]@{schemaVersion='aiw.dev/research/control-baseline/v0alpha1'; productionEvidence=$false; stage='setup'; cases=@(); error=$null; windowsBuild=[Environment]::OSVersion.Version.ToString()}
function Invoke-Control([string]$Case, [string]$Mode, [pscredential]$Credential) {
    $directory = 'C:\AIW\Control\' + $Case
    $stdout = Join-Path $directory 'stdout.json'
    $stderr = Join-Path $directory 'stderr.txt'
    $parameters = @{FilePath='C:\AIW\Control\aiw-control-fixture.exe'; ArgumentList=@('--mode',$Mode); WorkingDirectory=$directory; RedirectStandardOutput=$stdout; RedirectStandardError=$stderr; PassThru=$true; WindowStyle='Hidden'}
    if ($Credential) { $parameters.Credential=$Credential; $parameters.LoadUserProfile=$true }
    $process = Start-Process @parameters
    $null = $process.Handle
    try {
        if (!$process.WaitForExit(30000)) { $process.Kill(); $process.WaitForExit(5000) | Out-Null; throw 'Control process deadline exceeded' }
        $exit = $process.ExitCode
        if ((Get-Item -LiteralPath $stdout).Length -gt 16384 -or (Get-Item -LiteralPath $stderr).Length -gt 16384) { throw 'Control output limit exceeded' }
        $observation = Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json
        if ($observation.ownProcessToken.processId -ne $process.Id) { throw 'Root process token PID mismatch' }
        [ordered]@{case=$Case; exitCode=$exit; processId=$process.Id; observation=$observation}
    } finally { $process.Dispose() }
}
try {
    $expected = (Get-Content 'C:\AIW\Input\fixture.sha256' -Raw).Trim()
    if ((Get-FileHash 'C:\AIW\Input\aiw-control-fixture.exe').Hash.ToLowerInvariant() -ne $expected) { throw 'Fixture input drift' }
    $result.fixtureSha256 = $expected
    $password = ConvertTo-SecureString ([guid]::NewGuid().ToString()+'aA1!') -AsPlainText -Force
    $user = New-LocalUser -Name 'AiwControlUser' -Password $password -AccountNeverExpires
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user.Name
    $result.standardUserSid=$user.SID.Value
    $credential = [pscredential]::new('.\AiwControlUser',$password)
    New-Item -ItemType Directory 'C:\AIW\Control' | Out-Null
    Copy-Item 'C:\AIW\Input\aiw-control-fixture.exe' 'C:\AIW\Control\aiw-control-fixture.exe'
    & icacls.exe 'C:\AIW\Control' /grant 'AiwControlUser:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Control directory ACL failed' }
    foreach ($case in @('roundtrip','allow','deny','missing','child','failure')) { New-Item -ItemType Directory ('C:\AIW\Control\'+$case) | Out-Null }
    foreach ($case in @('allow','deny')) { [IO.File]::WriteAllText(('C:\AIW\Control\'+$case+'\canary.txt'),'AIW controlled readable bytes') }
    & icacls.exe 'C:\AIW\Control\deny\canary.txt' /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Negative-control ACL failed' }
    $result.stage='admin-read-control'
    $result.cases += Invoke-Control 'deny' 'read-canary' $null
    # Reuse the same resource with unchanged ACL, but publish each process output separately.
    Move-Item 'C:\AIW\Control\deny\stdout.json' 'C:\AIW\Control\deny\admin-stdout.json'
    Move-Item 'C:\AIW\Control\deny\stderr.txt' 'C:\AIW\Control\deny\admin-stderr.txt'
    $result.cases[0].case='admin-read'
    $result.stage='standard-user-controls'
    foreach ($pair in @(@('roundtrip','round-trip'),@('allow','read-canary'),@('deny','read-canary'),@('missing','read-canary'),@('child','child'),@('failure','expected-failure'))) {
        $result.cases += Invoke-Control $pair[0] $pair[1] $credential
    }
    if ((Get-FileHash 'C:\AIW\Control\aiw-control-fixture.exe').Hash.ToLowerInvariant() -ne $expected) { throw 'Fixture output drift' }
    $result.stage='finished'
} catch { $result.error=$_.Exception.Message }
$result | ConvertTo-Json -Depth 16 | Set-Content -Encoding UTF8 'C:\AIW\Output\control-result.pending.json'
Move-Item -LiteralPath 'C:\AIW\Output\control-result.pending.json' -Destination 'C:\AIW\Output\control-result.json'
