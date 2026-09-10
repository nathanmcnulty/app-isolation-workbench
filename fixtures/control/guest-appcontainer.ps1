# Fixed research launcher, only inside a disposable Windows Sandbox worker.
$ErrorActionPreference='Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount' -or !(Test-Path 'C:\AIW\Input\aiw-control-appcontainer.exe')) { throw 'Disposable guest required' }
$result=[ordered]@{schemaVersion='aiw.dev/research/control-appcontainer-guest/v0alpha2'; productionEvidence=$false; stage='setup'; error=$null; windowsBuild=[Environment]::OSVersion.Version.ToString()}
$registryBase=$null; $registryKey=$null
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
    & icacls.exe 'C:\AIW\Control' /grant 'AiwControlUser:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Control directory ACL failed' }
    New-Item -ItemType Directory 'C:\AIW\Control\SharedCanary' | Out-Null
    [IO.File]::WriteAllText('C:\AIW\Control\SharedCanary\canary.txt','AIW controlled readable bytes')
    & icacls.exe 'C:\AIW\Control\SharedCanary\canary.txt' /inheritance:r /grant:r 'AiwControlUser:R' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Paired canary ACL failed' }
    New-Item -ItemType Directory 'C:\AIW\Control\AppContainerChild' | Out-Null
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /inheritance:r /grant:r 'AiwControlUser:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory ACL failed' }
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /setowner 'AiwControlUser' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory ownership failed' }
    & icacls.exe 'C:\AIW\Control\AppContainerChild' /setintegritylevel '(OI)(CI)L' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Child directory integrity label failed' }
    $registryBase=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
    $existing=$registryBase.OpenSubKey('SOFTWARE\AIWControlCanary')
    if ($existing) { $existing.Dispose(); throw 'Fixed registry control already exists' }
    $registryKey=$registryBase.CreateSubKey('SOFTWARE\AIWControlCanary',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    $registryBytes=[Text.Encoding]::ASCII.GetBytes('AIW controlled registry bytes')
    $registryKey.SetValue('Canary',$registryBytes,[Microsoft.Win32.RegistryValueKind]::Binary)
    $acl=[Security.AccessControl.RegistrySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($principal in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@($user.SID.Value,'ReadKey'))) {
        $rule=[Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal[0]),[Security.AccessControl.RegistryRights]$principal[1],[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    $registryKey.SetAccessControl($acl)
    $registryAcl=$registryKey.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    $hasher=[Security.Cryptography.SHA256]::Create()
    try { $registryHash=[BitConverter]::ToString($hasher.ComputeHash($registryBytes)).Replace('-','').ToLowerInvariant() } finally { $hasher.Dispose() }
    $result.registryBinding=[ordered]@{hive='HKLM'; view='registry64'; key='SOFTWARE\AIWControlCanary'; value='Canary'; valueType='binary'; sha256=$registryHash; sizeBytes=$registryBytes.Length; valueUnchanged=$false; aclUnchanged=$false}
    $result.stage='paired-controls'
    $process=Start-Process -FilePath 'C:\AIW\Control\aiw-control-appcontainer.exe' -WorkingDirectory 'C:\AIW\Control' -Credential $credential -LoadUserProfile -RedirectStandardOutput 'C:\AIW\Control\launcher.json' -RedirectStandardError 'C:\AIW\Control\launcher.stderr' -WindowStyle Hidden -PassThru
    $null=$process.Handle
    try {
        $result.launcherProcessId=$process.Id
        if (!$process.WaitForExit(120000)) { $process.Kill(); $process.WaitForExit(5000) | Out-Null; throw 'AppContainer control deadline exceeded' }
        $result.launcherExitCode=$process.ExitCode
        if ((Get-Item 'C:\AIW\Control\launcher.json').Length -gt 49152 -or (Get-Item 'C:\AIW\Control\launcher.stderr').Length -gt 16384) { throw 'Launcher output exceeded bounds' }
        $result.launcherStderr=Get-Content 'C:\AIW\Control\launcher.stderr' -Raw
        $result.observation=Get-Content 'C:\AIW\Control\launcher.json' -Raw | ConvertFrom-Json
        if ($process.ExitCode -ne 0) { throw "Launcher failed with exit $($process.ExitCode)" }
    } finally { $process.Dispose() }
    $result.registryBinding.valueUnchanged=$registryKey.GetValueKind('Canary') -eq [Microsoft.Win32.RegistryValueKind]::Binary -and [Convert]::ToBase64String($registryKey.GetValue('Canary')) -ceq [Convert]::ToBase64String($registryBytes)
    $result.registryBinding.aclUnchanged=$registryKey.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -ceq $registryAcl
    if (!$result.registryBinding.valueUnchanged -or !$result.registryBinding.aclUnchanged) { throw 'Registry control changed during trial' }
    foreach ($entry in @(@('aiw-control-fixture.exe',$fixtureHash),@('aiw-control-appcontainer.exe',$launcherHash))) {
        if ((Get-FileHash -LiteralPath ('C:\AIW\Control\'+$entry[0])).Hash.ToLowerInvariant() -ne $entry[1]) { throw 'Control executable changed during trial' }
    }
    $result.stage='finished'
} catch { $result.error=$_.Exception.Message } finally {
    if ($registryKey) { $registryKey.Dispose() }
    if ($registryBase) { $registryBase.Dispose() }
}
$result | ConvertTo-Json -Depth 24 | Set-Content -Encoding UTF8 'C:\AIW\Output\control-result.pending.json'
Move-Item -LiteralPath 'C:\AIW\Output\control-result.pending.json' -Destination 'C:\AIW\Output\control-result.json'
