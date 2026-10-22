#requires -Version 5.1
# One fixed, explicitly authorized reset of the cloned labadmin profile.
# This is preparation, not an application trial or a generic cleanup interface.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Set-StrictMode -Version Latest

function Assert-AiwWorker107ProfileContext {
    param([string]$ActorSid, [int]$SessionId, [bool]$Impersonating,
        [string]$Uuid, [object[]]$Accounts, [object[]]$Profiles)
    if ($ActorSid -cne 'S-1-5-18' -or $SessionId -ne 0 -or $Impersonating -or
        $Uuid.ToLowerInvariant() -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e') {
        throw 'Fixed worker SYSTEM context required'
    }
    $sid = 'S-1-5-21-3556347314-2314855617-1438300668-1001'
    $account = @($Accounts | Where-Object SID -CEQ $sid)
    if ($account.Count -ne 1 -or $account[0].Name -cne 'labadmin' -or
        $account[0].Disabled -isnot [bool] -or $account[0].Disabled) {
        throw 'Fixed existing labadmin account required'
    }
    $profile = @($Profiles | Where-Object SID -CEQ $sid)
    $samePath = @($Profiles | Where-Object LocalPath -EQ 'C:\Users\labadmin')
    if ($profile.Count -ne 1 -or $samePath.Count -ne 1 -or
        $samePath[0].SID -cne $sid -or $profile[0].LocalPath -ine 'C:\Users\labadmin' -or
        $profile[0].Loaded -isnot [bool] -or $profile[0].Loaded -or
        $profile[0].Special -isnot [bool] -or $profile[0].Special) {
        throw 'Exact unloaded nonspecial labadmin profile required'
    }
}

function Get-AiwResetAccounts {
    @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' |
        Sort-Object SID | Select-Object Name,SID,Disabled)
}
function Get-AiwResetProfiles {
    @(Get-CimInstance Win32_UserProfile | Sort-Object SID |
        Select-Object SID,LocalPath,Loaded,Special)
}
function Write-AiwResetRecord {
    param([string]$Name, [object]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 10))
    $file = [IO.FileStream]::new((Join-Path $evidence $Name), [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
    finally { $file.Dispose() }
}

if ($args.Count -ne 0) { throw 'Profile reset accepts no arguments' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$session = [Diagnostics.Process]::GetCurrentProcess().SessionId
$impersonating = $null -ne [Security.Principal.WindowsIdentity]::GetCurrent($true)
if ($identity.User.Value -cne 'S-1-5-18' -or $session -ne 0 -or $impersonating) {
    throw 'Fixed worker SYSTEM context required'
}
$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$accountsBefore = @(Get-AiwResetAccounts)
$profilesBefore = @(Get-AiwResetProfiles)
Assert-AiwWorker107ProfileContext $identity.User.Value $session $impersonating $uuid $accountsBefore $profilesBefore
$sid = 'S-1-5-21-3556347314-2314855617-1438300668-1001'
$profilePath = 'C:\Users\labadmin'
foreach ($path in @('C:\Users', $profilePath)) {
    $item = Get-Item -LiteralPath $path -Force
    if (!$item.PSIsContainer -or $item.FullName -ine $path -or
        (Resolve-Path -LiteralPath $path).ProviderPath -ine $path -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Fixed regular profile path required'
    }
}
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid
if ((Get-ItemProperty -LiteralPath $registryPath -Name ProfileImagePath).ProfileImagePath -ine $profilePath) {
    throw 'Profile registry path differs'
}
$evidence = 'C:\AIW-Worker107-Profile-Reset-r1'
if (Test-Path -LiteralPath $evidence) { throw 'Preserve the existing reset attempt; do not retry' }
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl.SetOwner($systemSid)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($systemSid,
    'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[IO.Directory]::CreateDirectory($evidence, $acl) | Out-Null
$actual = Get-Acl -LiteralPath $evidence
$rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18' -or
    $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -cne 'S-1-5-18' -or
    $rules[0].AccessControlType -ne 'Allow' -or $rules[0].IsInherited -or
    (Get-Item -LiteralPath $evidence -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Protected reset evidence directory required'
}
$stage = 'before'
try {
    Write-AiwResetRecord 'before.json' ([ordered]@{
        schemaVersion = 'aiw.dev/worker107-profile-reset-before/v1'
        observedUtc = [DateTime]::UtcNow.ToString('o'); workerVmId = 107
        smbiosUuid = $uuid.ToLowerInvariant(); targetSid = $sid; targetPath = $profilePath
        actorSid = $identity.User.Value; sessionId = $session
        accounts = $accountsBefore; profiles = $profilesBefore
    })
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class AiwWorker107Userenv {
    [DllImport(@"C:\Windows\System32\userenv.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteProfileW(string sid, string profilePath, string computer);
    [DllImport(@"C:\Windows\System32\userenv.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
    public static extern int CreateProfile(string sid, string userName, StringBuilder profilePath, uint characters);
}
'@
    # Recheck immediately before the only destructive native call.
    Assert-AiwWorker107ProfileContext $identity.User.Value $session $impersonating $uuid @(Get-AiwResetAccounts) @(Get-AiwResetProfiles)
    $stage = 'delete-profile'
    if (![AiwWorker107Userenv]::DeleteProfileW($sid, $profilePath, $null)) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ((Test-Path -LiteralPath $profilePath) -or (Test-Path -LiteralPath $registryPath)) {
        throw 'Native deletion left profile path or registration present'
    }
    Write-AiwResetRecord 'deleted.json' ([ordered]@{ observedUtc = [DateTime]::UtcNow.ToString('o'); targetSid = $sid; profileDeleted = $true })
    $stage = 'create-profile'
    $createdPath = [Text.StringBuilder]::new(260)
    $hr = [AiwWorker107Userenv]::CreateProfile($sid, 'labadmin', $createdPath, 260)
    if ($hr -ne 0) { [Runtime.InteropServices.Marshal]::ThrowExceptionForHR($hr); throw 'CreateProfile did not return S_OK' }
    if ($createdPath.ToString() -ine $profilePath) { throw 'Created profile path differs' }
    $stage = 'verify'
    $accountsAfter = @(Get-AiwResetAccounts)
    $profilesAfter = @(Get-AiwResetProfiles)
    Assert-AiwWorker107ProfileContext $identity.User.Value $session $impersonating $uuid $accountsAfter $profilesAfter
    if (($accountsBefore | ConvertTo-Json -Compress) -cne ($accountsAfter | ConvertTo-Json -Compress)) {
        throw 'Local account inventory changed'
    }
    $copiedAuthPaths = @('.ssh', '.azure', '.codex' | ForEach-Object {
        [ordered]@{ path = (Join-Path $profilePath $_); present = [bool](Test-Path -LiteralPath (Join-Path $profilePath $_)) }
    })
    if (@($copiedAuthPaths | Where-Object present).Count -ne 0) { throw 'Fresh profile contains copied development auth paths' }
    $result = [ordered]@{
        schemaVersion = 'aiw.dev/worker107-profile-reset/v1'; completedUtc = [DateTime]::UtcNow.ToString('o')
        workerVmId = 107; smbiosUuid = $uuid.ToLowerInvariant(); targetSid = $sid; targetPath = $profilePath
        accountName = 'labadmin'; accountInventoryPreserved = $true; profileRecreated = $true
        copiedAuthPathPresence = $copiedAuthPaths; specialProfilesTargeted = $false
        applicationTrialExecuted = $false; evidence = $evidence
    }
    Write-AiwResetRecord 'result.json' $result
    $result | ConvertTo-Json -Depth 10
} catch {
    Write-AiwResetRecord 'failure.json' ([ordered]@{ stage = $stage; observedUtc = [DateTime]::UtcNow.ToString('o'); error = $_.Exception.Message })
    throw
}
