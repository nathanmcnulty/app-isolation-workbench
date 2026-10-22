#requires -Version 7.6
# Offline, console-owned setup only. Never run on the PASSKEYS controller.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Worker106Setup([object]$Observed) {
    if ($Observed.VmUuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM UUID' }
    if ($Observed.Computer -cne 'PASSKEYS') { throw 'Unexpected computer name' }
    if ($Observed.UserSid -cne 'S-1-5-21-3849540285-1795134874-2442050430-1001') { throw 'Unexpected operator SID' }
    if (-not $Observed.Elevated -or -not $Observed.Is64Bit) { throw 'Elevated x64 PowerShell required' }
    if ($Observed.DomainJoined -or $Observed.AzureAdJoined -cne 'NO' -or $Observed.EnterpriseJoined -cne 'NO') { throw 'Joined-device state requires separate review; no deregistration performed' }
    if ($Observed.Adapters.Count -ne 1 -or $Observed.Adapters[0].MacAddress -cne 'CC-34-21-7E-FE-59' -or $Observed.Adapters[0].Status -cne 'Disconnected') { throw 'Exact disconnected physical adapter required' }
    if ($Observed.AdminExists -or $Observed.StageExists) { throw 'Preserve previous account/setup evidence; do not rerun or adopt it' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$vm = Get-CimInstance Win32_ComputerSystemProduct
# Refuse the controller before observing or changing any service or account.
if ($vm.UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM; stop here' }
$computer = Get-CimInstance Win32_ComputerSystem
$registration = (& "$env:WINDIR\System32\dsregcmd.exe" /status) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Cannot observe Windows device registration' }
$joinState = @{}
foreach ($field in @('AzureAdJoined','EnterpriseJoined')) {
    $values = [regex]::Matches($registration, "(?m)^\s*$field\s*:\s*(YES|NO)\s*$")
    if ($values.Count -ne 1) { throw "Unmeasured registration field: $field" }
    $joinState[$field] = $values[0].Groups[1].Value
}
$registration = $null
$adminName = 'AiwWorkerAdmin'
$stage = 'C:\AIW-Worker-Setup'
$users = @(Get-LocalUser)
$adapters = @(Get-NetAdapter -Physical | ForEach-Object {
    [pscustomobject]@{ MacAddress = $_.MacAddress; Status = $_.Status.ToString() }
})
$observed = [pscustomobject]@{
    VmUuid = $vm.UUID; Computer = $env:COMPUTERNAME; UserSid = $identity.User.Value
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Is64Bit = [Environment]::Is64BitProcess; DomainJoined = $computer.PartOfDomain
    AzureAdJoined = $joinState.AzureAdJoined; EnterpriseJoined = $joinState.EnterpriseJoined
    Adapters = $adapters; AdminExists = @($users | Where-Object Name -IEQ $adminName).Count -ne 0
    StageExists = Test-Path -LiteralPath $stage
}
Assert-Worker106Setup $observed
$copiedAccounts = @('CodexSandboxOffline','CodexSandboxOnline')
foreach ($name in $copiedAccounts) {
    $matches = @($users | Where-Object Name -CEQ $name)
    if ($matches.Count -ne 1 -or $matches[0].SID.AccountDomainSid.Value -cne $identity.User.AccountDomainSid.Value) { throw "Unexpected copied account: $name" }
}
$service = Get-Service -Name Tailscale -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $stage -AclObject $acl
$state = [ordered]@{ SchemaVersion = 1; VmUuid = $vm.UUID; OperatorSid = $identity.User.Value; Phase = 'PreflightPassed'; Operations = @(); Result = 'inProgress' }
function Save-Worker106Stage([string]$Phase) {
    $state.Phase = $Phase
    $state.Utc = [DateTime]::UtcNow.ToString('o')
    $state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'bootstrap.json') -Encoding utf8
}
try {
    Save-Worker106Stage 'PreflightPassed'
    if ($null -ne $service) {
        Set-Service -Name Tailscale -StartupType Disabled
        if ($service.Status -ne 'Stopped') { Stop-Service -Name Tailscale }
        (Get-Service Tailscale).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        $service = Get-Service Tailscale
        if ($service.Status -ne 'Stopped' -or $service.StartType -ne 'Disabled') { throw 'Tailscale stop/disable not verified' }
        $state.Operations += 'Tailscale stopped and disabled; local state not deleted'
    } else {
        $state.Operations += 'Tailscale service absent; remaining local state not yet measured'
    }
    Save-Worker106Stage 'CopiedVpnDisabled'
    $password = Read-Host 'Choose a new password for AiwWorkerAdmin (worker only)' -AsSecureString
    try {
        $admin = New-LocalUser -Name $adminName -Password $password -Description 'Dedicated VM 106 worker administrator' -AccountNeverExpires
    } finally { if ($null -ne $password) { $password.Dispose(); $password = $null } }
    $state.AdminSid = $admin.SID.Value
    Save-Worker106Stage 'AdministratorCreated'
    $administratorGroup = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    Add-LocalGroupMember -SID $administratorGroup -Member $admin.SID.Value
    if (@(Get-LocalGroupMember -SID $administratorGroup | Where-Object { $_.SID.Value -ceq $admin.SID.Value }).Count -ne 1) { throw 'Fresh administrator membership not verified' }
    if (-not (Get-LocalUser -SID $admin.SID).Enabled) { throw 'Fresh administrator is disabled' }
    $state.Operations += 'Fresh worker administrator created and membership verified'
    foreach ($name in $copiedAccounts) {
        $user = $users | Where-Object Name -CEQ $name
        Disable-LocalUser -SID $user.SID
        if ((Get-LocalUser -SID $user.SID).Enabled) { throw "Copied account remains enabled: $name" }
        $state.Operations += "Disabled copied account: $name"
    }
    Save-Worker106Stage 'CopiedCodexAccountsDisabled'
    $rename = Rename-Computer -NewName 'PASSKEYS-WORKER' -Force -PassThru
    if (-not $rename.HasSucceeded) { throw 'Computer rename did not succeed' }
    $state.Operations += 'Computer rename staged; reboot required'
    $state.Result = 'setupCompleteAwaitingRebootAndFreshAdminLogin'
    $state.LabadminRetained = (Get-LocalUser -SID $identity.User).Enabled
    $state.CopiedCaches = 'retained; no sign-out, revocation or deletion performed'
    $state.StandardTrialUser = 'not created; prepare only when the test window is ready'
    Save-Worker106Stage 'AwaitingRebootAndFreshAdminLogin'
    $state | ConvertTo-Json -Depth 5
} catch {
    $state.Result = 'failedPreserveEvidenceDoNotRerun'
    $state.Error = $_.Exception.Message
    Save-Worker106Stage 'SetupFailed'
    throw
}
