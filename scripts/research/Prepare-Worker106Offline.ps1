param([Parameter(Mandatory=$true)][ValidateSet('Prepare','Verify','Finalize','State')][string]$Operation)
# Fixed offline setup boundary; no command text, paths or credentials accepted.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$stage='C:\AIW-Worker-Setup'
$adminName='AiwWorkerAdmin'
$machineSid='S-1-5-21-3849540285-1795134874-2442050430'
$password=$null; $secure=$null; $rsa=$null; $random=$null

function Assert-OfflineIdentity([object]$o) {
    if ($o.Uuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $o.Sid -cne 'S-1-5-18' -or -not $o.Is64Bit) { throw 'Worker SYSTEM identity required' }
    if ($o.Adapters.Count -ne 1 -or $o.Adapters[0].MacAddress -cne 'CC-34-21-7E-FE-59' -or $o.Adapters[0].Status -ne 'Disconnected') { throw 'Exact disconnected worker adapter required' }
    if ($o.DomainJoined -or $o.AzureAdJoined -cne 'NO' -or $o.EnterpriseJoined -cne 'NO') { throw 'Machine join state requires review' }
    if ($o.ServiceCount -ne 0 -or $o.TailscalePathsPresent) { throw 'Tailscale cleanup must remain complete' }
}

function Assert-PlainDirectory([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or $item.FullName -ine $Path) { throw 'Unexpected directory' }
    while ($null -ne $item) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse directory refused' }
        $item=$item.Parent
    }
}

function Save-Stage([string]$Phase) {
    $script:state.Phase=$Phase
    $script:state.Utc=[DateTime]::UtcNow.ToString('o')
    $script:state | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath "$stage\bootstrap.json" -Encoding UTF8
}

try {
    $vm=Get-CimInstance Win32_ComputerSystemProduct
    if ($vm.UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM' }
    $computer=Get-CimInstance Win32_ComputerSystem
    $registration=(& "$env:WINDIR\System32\dsregcmd.exe" /status) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Device join measurement failed' }
    $join=@{}
    foreach ($field in @('AzureAdJoined','EnterpriseJoined')) {
        $matches=[regex]::Matches($registration,"(?m)^\s*$field\s*:\s*(YES|NO)\s*$")
        if ($matches.Count -ne 1) { throw 'Ambiguous device join measurement' }
        $join[$field]=$matches[0].Groups[1].Value
    }
    $registration=$null
    Assert-OfflineIdentity ([pscustomobject]@{
        Uuid=$vm.UUID; Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Is64Bit=[Environment]::Is64BitProcess
        Adapters=@(Get-NetAdapter -Physical); DomainJoined=$computer.PartOfDomain
        AzureAdJoined=$join.AzureAdJoined; EnterpriseJoined=$join.EnterpriseJoined
        ServiceCount=@(Get-CimInstance Win32_Service -Filter "Name='Tailscale'").Count
        TailscalePathsPresent=@(@('C:\ProgramData\Tailscale','C:\Users\labadmin\AppData\Local\Tailscale','C:\Windows\System32\config\systemprofile\AppData\Local\Tailscale') | Where-Object { Test-Path -LiteralPath $_ }).Count -ne 0
    })
    if ($Operation -eq 'State') {
        Assert-PlainDirectory $stage
        $saved=Get-Content -LiteralPath "$stage\bootstrap.json" -Raw | ConvertFrom-Json
        if ($saved.VmUuid -ine $vm.UUID -or $saved.AdminName -cne $adminName) {throw 'Preparation state identity mismatch'}
        $saved | ConvertTo-Json -Depth 7 -Compress
        exit 0
    }
    $lab=Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]::new("$machineSid-1001"))
    if ($lab.Name -cne 'labadmin') { throw 'Copied account identity changed' }
    $copied=@(foreach($name in @('CodexSandboxOffline','CodexSandboxOnline')) {
        $u=Get-LocalUser -Name $name
        if ($u.SID.AccountDomainSid.Value -cne $machineSid) { throw 'Copied sandbox SID mismatch' }
        $u
    })
    $adminGroup=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    if ($Operation -eq 'Prepare') {
        if ($env:COMPUTERNAME -cne 'PASSKEYS' -or -not $lab.Enabled -or (Test-Path -LiteralPath $stage) -or @(Get-LocalUser | Where-Object Name -IEQ $adminName).Count) { throw 'Unexpected or previously prepared worker; preserve evidence' }
        if (Test-Path -LiteralPath "C:\Users\$adminName") { throw 'Fresh profile path already occupied' }
        Assert-PlainDirectory 'C:\Users'
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        }
        # Establish the final ACL at directory creation, before any state/secret.
        [void][IO.Directory]::CreateDirectory($stage,$acl)
        $script:state=[ordered]@{SchemaVersion=1;VmUuid=$vm.UUID;Phase='PreflightPassed';AdminName=$adminName;AdminSid=$null;CredentialCiphertext=$null;ProfilePath=$null;CredentialLogonValidated=$false;Result='inProgress';LabadminRetained=$true;StandardTrialUser='not created'}
        Save-Stage 'PreflightPassed'
        $random=New-Object byte[] 30
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random) } finally { $rng.Dispose() }
        $password='Aa9!'+[Convert]::ToBase64String($random)
        $rsa=[Security.Cryptography.RSACng]::new()
        $parameters=[Security.Cryptography.RSAParameters]::new()
        $parameters.Modulus=[Convert]::FromBase64String('yFwU/upf0NT8iht7pmrVhUrg+3weWAJFGty/JBEMFUA8m+FFCwtdTpDRknuFkPRToiunawMqmG5mDsaZqFBXHZSh2fjHBcds5fUAMLsFK0vj9sRtFTozj8LzLlAdOK/eDHNZad6gYMyFbGkY0ovR1aDQDki4BW1P5dhrgtR2qGr4fJwQFWKTgxrVhMBwOpnTxlNDaHxgHau2AhAFhmYqTNvHP/iuZ4QQR3iQsQ/5VI28juxUI5sE2F+X7i0pDHnS8cPOo4F4kBSW1pW01G9pzZ0N4la2kTHQGbCWSbHsj9CZ29NKHOdKrGmB4kiNyEgnE3oGPDopj8DN1O9e902hFPJHlefj+qEpJ7sZAy+OM4z229o+kge2H3ZZrEA+UF9jO8uQ582+udxcMAYzuQkOGxZ4CymLcht+lODOh/+TuXeWI6d0Ug2WeiKLbi9R3bN/rLn0lHlmjYpOWgnczSIh8GizWVMjnrq5D5NRMtSeGMmxI5n2ohLZSGYevGi2dcMB')
        $parameters.Exponent=[Convert]::FromBase64String('AQAB')
        $rsa.ImportParameters($parameters)
        $state.CredentialCiphertext=[Convert]::ToBase64String($rsa.Encrypt([Text.Encoding]::UTF8.GetBytes($password),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        Save-Stage 'CredentialSealedBeforeAccountCreation'
        $secure=ConvertTo-SecureString $password -AsPlainText -Force
        $admin=New-LocalUser -Name $adminName -Password $secure -Description 'Dedicated offline VM 106 administrator' -AccountNeverExpires -PasswordNeverExpires
        $state.AdminSid=$admin.SID.Value
        Save-Stage 'AdministratorCreated'
        Add-LocalGroupMember -SID $adminGroup -Member $admin.SID.Value
        if (@(Get-LocalGroupMember -SID $adminGroup | Where-Object {$_.SID.Value -ceq $admin.SID.Value}).Count -ne 1) { throw 'Administrator membership not verified' }
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Worker106Native {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
 public static extern int CreateProfile(string sid, string user, StringBuilder path, uint length);
}
'@
        $token=[IntPtr]::Zero
        if (-not [Worker106Native]::LogonUser($adminName,$env:COMPUTERNAME,$password,2,0,[ref]$token)) { throw ('Credential logon failed: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        try {
            $loggedOn=[Security.Principal.WindowsIdentity]::new($token)
            try { if ($loggedOn.User.Value -cne $admin.SID.Value) { throw 'Credential token SID mismatch' } } finally {$loggedOn.Dispose()}
            $state.CredentialLogonValidated=$true
        } finally { [void][Worker106Native]::CloseHandle($token) }
        $profile=[Text.StringBuilder]::new(260)
        $hr=[Worker106Native]::CreateProfile($admin.SID.Value,$adminName,$profile,260)
        if ($hr -ne 0) { throw ('Fresh profile creation failed: '+$hr) }
        if ($profile.ToString() -cne "C:\Users\$adminName") { throw 'Unexpected fresh profile path' }
        Assert-PlainDirectory $profile.ToString()
        $state.ProfilePath=$profile.ToString()
        Save-Stage 'FreshAdministratorAndProfileVerified'
        foreach($u in $copied) { Disable-LocalUser -SID $u.SID; if ((Get-LocalUser -SID $u.SID).Enabled) {throw 'Copied account disable failed'} }
        Save-Stage 'CopiedSandboxAccountsDisabled'
        $rename=Rename-Computer -NewName 'PASSKEYS-WORKER' -Force -PassThru
        if (-not $rename.HasSucceeded) {throw 'Rename failed'}
        $state.Result='awaitingRebootAndFreshAdministratorConsoleLogin'
        Save-Stage 'PreparedAwaitingReboot'
        $state | ConvertTo-Json -Depth 7 -Compress
    } else {
        Assert-PlainDirectory $stage
        $script:state=Get-Content -LiteralPath "$stage\bootstrap.json" -Raw | ConvertFrom-Json
        if ($state.VmUuid -ine $vm.UUID -or $state.AdminName -cne $adminName -or $state.Phase -notin @('PreparedAwaitingReboot','Finalized')) { throw 'Setup stage not ready; preserve evidence' }
        if ($env:COMPUTERNAME -cne 'PASSKEYS-WORKER') { throw 'Worker rename not active; reboot required' }
        $admin=Get-LocalUser -Name $adminName
        if ($admin.SID.Value -cne $state.AdminSid -or $admin.SID.AccountDomainSid.Value -cne $machineSid -or -not $admin.Enabled) { throw 'Fresh administrator identity mismatch' }
        if (@(Get-LocalGroupMember -SID $adminGroup | Where-Object {$_.SID.Value -ceq $admin.SID.Value}).Count -ne 1) { throw 'Fresh administrator membership mismatch' }
        if (@($copied | Where-Object Enabled).Count) {throw 'Copied sandbox account enabled'}
        Assert-PlainDirectory "C:\Users\$adminName"
        $registeredProfile=Get-CimInstance Win32_UserProfile | Where-Object SID -CEQ $admin.SID.Value
        if (@($registeredProfile).Count -ne 1 -or $registeredProfile.LocalPath -cne "C:\Users\$adminName") { throw 'Fresh profile registration mismatch' }
        $tools=@(foreach($path in @('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.7.0_x64__8wekyb3d8bbwe\pwsh.exe','C:\Program Files\dotnet\dotnet.exe','C:\Program Files\nodejs\node.exe','C:\Program Files\Git\cmd\git.exe','C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe','C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\makeappx.exe','C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe')) {
            [pscustomobject]@{Path=$path;Exists=Test-Path -LiteralPath $path -PathType Leaf;FileVersion=if(Test-Path -LiteralPath $path -PathType Leaf){(Get-Item -LiteralPath $path).VersionInfo.FileVersion}else{$null}}
        })
        if (@($tools | Where-Object {-not $_.Exists}).Count) {
            # Retain the full observation before failing; never hide the missing
            # path behind an opaque terminal error or claim it was installed.
            [ordered]@{Failure='RequiredSystemToolMissing';Computer=$env:COMPUTERNAME;VmUuid=$vm.UUID;Tools=$tools} | ConvertTo-Json -Depth 5 -Compress
            throw 'Required system tool path missing; see captured inventory'
        }
        $interactive=$computer.UserName
        if ($Operation -eq 'Finalize') {
            if ($interactive -ine "PASSKEYS-WORKER\$adminName" -or -not $registeredProfile.Loaded) { throw 'Fresh administrator must be signed in at interactive console before finalization' }
            Disable-LocalUser -SID $lab.SID
            if ((Get-LocalUser -SID $lab.SID).Enabled) {throw 'Copied labadmin disable failed'}
            $state.LabadminRetained=$false
            $state.Result='offlinePreparationComplete'
            Save-Stage 'Finalized'
        }
        [ordered]@{VmUuid=$vm.UUID;Computer=$env:COMPUTERNAME;Phase=$state.Phase;AdminName=$adminName;AdminSid=$admin.SID.Value;AdminEnabled=$admin.Enabled;ProfilePath=$registeredProfile.LocalPath;ProfileLoaded=$registeredProfile.Loaded;InteractiveUser=$interactive;LabadminEnabled=(Get-LocalUser -SID $lab.SID).Enabled;CopiedSandboxAccountsDisabled=$true;TailscaleAbsent=$true;Network='Disconnected';Tools=$tools;CopiedProfileCaches='retained, offline; not adopted by fresh account';StandardTrialUser='not created';WindowsRegistrationChanged=$false;BootUtc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')} | ConvertTo-Json -Depth 7 -Compress
    }
} catch {
    if ($Operation -eq 'Prepare' -and $null -ne (Get-Variable -Name state -Scope Script -ErrorAction SilentlyContinue)) {
        $state.Result='failedPreserveEvidence'
        Save-Stage 'SetupFailed'
    }
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
} finally {
    $password=$null
    if ($null -ne $secure) {$secure.Dispose()}
    if ($null -ne $rsa) {$rsa.Dispose()}
    if ($null -ne $random) {[Array]::Clear($random,0,$random.Length)}
}
exit 0
