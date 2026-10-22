#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Stage','Enroll','ClearLogon','Prepare','Control','Trial','Edit','Status','Export')][string]$Operation)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$root = 'C:\AIW-Worker107-Research-r1'
$inputRoot = 'C:\AIW-Msix-Lifecycle-Input'
$outputRoot = 'C:\AIW-Msix-Lifecycle-Output'
$preparationPath = 'C:\AIW-Msix-Lifecycle-Preparation.json'
$uuid = 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'
$operatorSid = 'S-1-5-21-3556347314-2314855617-1438300668-1001'
$actor=[Security.Principal.WindowsIdentity]::GetCurrent()
$adminRead=($Operation -eq 'Status' -and $actor.User.Value -ceq $operatorSid -and
    ([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (!$adminRead -and ($actor.User.Value -cne 'S-1-5-18' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0 -or
    $null -ne [Security.Principal.WindowsIdentity]::GetCurrent($true))) { throw 'SYSTEM session zero without impersonation required' }
if ((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $uuid) { throw 'Exact worker107 required' }
function Assert-RegularPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.FullName -ine $Path -or (Resolve-Path -LiteralPath $Path).ProviderPath -ine $Path) { throw 'Fixed regular path required' }
}
function Set-ProtectedAcl([string]$Path, [string]$Reader = '') {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($operatorSid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    if ($Reader) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Reader),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')) }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function New-ProtectedDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw ('Fresh directory required: ' + $Path) }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-18'),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($operatorSid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    Assert-RegularPath $Path
}
function Write-Record([string]$Name, [object]$Value) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 12))
    $file = [IO.FileStream]::new((Join-Path $root $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
}
function Read-Record([string]$Name) {
    $path = Join-Path $root $Name
    Assert-RegularPath $path
    if ((Get-Item -LiteralPath $path).Length -gt 65536) { throw 'Record exceeds bound' }
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}
function Assert-OwnedAccount($Account) {
    if ($Account.schemaVersion -cne 'aiw.dev/research-primary-account/v1' -or $Account.vmId -cne $uuid -or
        $Account.accountName -cne 'AiwStandardUser' -or $Account.accountCreated -isnot [bool] -or !$Account.accountCreated -or
        $Account.runNonce -cnotmatch '\A[0-9a-f]{64}\z' -or
        $Account.userSid -cnotmatch '\AS-1-5-21-3556347314-2314855617-1438300668-[0-9]+\z' -or
        $Account.userSid -ceq $operatorSid) { throw 'Run-owned account receipt required' }
    $actual = Get-LocalUser -Name AiwStandardUser
    if ($actual.SID.Value -cne $Account.userSid -or
        (!$actual.Enabled -and $Operation -notin @('ClearLogon','Export'))) { throw 'Run-owned account differs' }
}
function Assert-AutomaticSignInCleared {
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$false)
    try {
        if('DefaultPassword' -in $key.GetValueNames() -or $key.GetValue('AutoAdminLogon') -eq '1' -or 'AutoLogonCount' -in $key.GetValueNames()){throw 'Temporary automatic sign-in material must be cleared before testing/export'}
    }finally{$key.Dispose()}
}
if ($Operation -eq 'Stage') {
    Assert-RegularPath 'C:\'
    New-ProtectedDirectory $root
    Write-Record 'Stage.started.json' @{ workerVmId=107; uuid=$uuid; startedUtc=[DateTime]::UtcNow.ToString('o') }
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'bundle.json') -Raw | ConvertFrom-Json
        if ($manifest.schemaVersion -cne 'aiw.dev/worker107-msix-bundle/v1' -or $manifest.workerUuid -cne $uuid) { throw 'Bundle identity differs' }
        $names = @($manifest.files | ForEach-Object { $_.name })
        if (($names | Sort-Object -Unique).Count -ne $names.Count) { throw 'Duplicate bundle names' }
        foreach ($entry in $manifest.files) {
            if ($entry.name -cnotmatch '\A[a-zA-Z0-9_.-]+\z' -or $entry.sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Closed bundle file identity malformed' }
            $source = Join-Path $PSScriptRoot $entry.name
            Assert-RegularPath $source
            if ((Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -cne $entry.sha256) { throw ('Bundle hash differs: ' + $entry.name) }
            Copy-Item -LiteralPath $source -Destination (Join-Path $root $entry.name)
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'bundle.json') -Destination (Join-Path $root 'bundle.json')
        New-ProtectedDirectory $inputRoot
        New-ProtectedDirectory $outputRoot
        New-ProtectedDirectory 'C:\AIW-Worker107-UI-r1'
        foreach($name in @('worker107-editor.ps1','worker107-editor-input.cs','research_msix_native.cs','research_msix_interactive.cs')) {
            Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path 'C:\AIW-Worker107-UI-r1' $name)
        }
        foreach ($name in @('application.msix','assembly.json','signing.json','msix_standard_user_lifecycle.exe')) {
            Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $inputRoot $name)
        }
        if ((Get-AuthenticodeSignature -LiteralPath (Join-Path $inputRoot 'application.msix')).Status -ne 'Valid') { throw 'Signed MSIX validation failed' }
        if (@(Get-LocalUser -Name AiwStandardUser -ErrorAction SilentlyContinue).Count -ne 0 -or
            @(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP).Count -ne 0 -or
            @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Fresh research account/package/process inventory required' }
        $cmdHash = (Get-FileHash -LiteralPath 'C:\Windows\System32\cmd.exe').Hash.ToLowerInvariant()
        if ((Get-AuthenticodeSignature -LiteralPath 'C:\Windows\System32\cmd.exe').Status -ne 'Valid') { throw 'OS control signature invalid' }
        Write-Record 'baseline.json' @{ workerVmId=107; vmId=$uuid; checkpoint='aiw-msix-worker107-clean-r1'; cmdSha256=$cmdHash; driverSha256=$manifest.driverSha256; sourceCommit=$manifest.sourceCommit; observedUtc=[DateTime]::UtcNow.ToString('o') }
        Write-Record 'Stage.result.json' @{ staged=$true; applicationExecuted=$false; accountCreated=$false }
    } catch { Write-Record 'Stage.failure.json' @{error=$_.Exception.Message}; throw }
    Read-Record 'Stage.result.json' | ConvertTo-Json
    return
}
Assert-RegularPath $root
if ((Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-18') { throw 'SYSTEM staging owner required' }
if ($Operation -eq 'Status') {
    $records = [ordered]@{}
    foreach ($name in @('Stage','Enroll','Prepare','Control','Trial','Edit')) {
        foreach ($suffix in @('started','result','failure')) {
            $file = "$name.$suffix.json"
            if (Test-Path -LiteralPath (Join-Path $root $file)) { $records[$file] = Read-Record $file }
        }
    }
    $workflow = 'C:\Users\AiwStandardUser\AppData\Local\AIW\msix-lifecycle'
    $stages = @()
    if (Test-Path -LiteralPath $workflow) {
        Assert-RegularPath $workflow
        $stages = @(Get-ChildItem -LiteralPath $workflow -File | Select-Object Name,Length)
    }
    [ordered]@{ workerVmId=107; records=$records; applicationStages=$stages; observedUtc=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 14
    return
}
. (Join-Path $root 'msix-primary-preparation.ps1')
. (Join-Path $root 'worker107-msix-templates.ps1')
if ($Operation -eq 'Enroll') {
    if (Test-Path -LiteralPath (Join-Path $root 'Enroll.started.json')) { throw 'Preserve existing account attempt; no retry' }
    if (@(Get-LocalUser -Name AiwStandardUser -ErrorAction SilentlyContinue).Count -ne 0) { throw 'Refuse existing trial account' }
    $winlogon = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
    $secure=$null; $password=$null
    try {
        if ('DefaultPassword' -in $winlogon.GetValueNames() -or $winlogon.GetValue('AutoAdminLogon') -eq '1') { throw 'Refuse preexisting automatic sign-in' }
        Write-Record 'Enroll.started.json' @{startedUtc=[DateTime]::UtcNow.ToString('o'); autoSignInPlanned=$true}
        $random = [byte[]]::new(32); $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random); $password = 'Aa9!'+[Convert]::ToBase64String($random) } finally { $rng.Dispose(); [Array]::Clear($random,0,$random.Length) }
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        $before = [DateTime]::UtcNow.ToFileTimeUtc()
        $user = New-LocalUser -Name AiwStandardUser -Password $secure -AccountExpires ([DateTime]::UtcNow.AddMinutes(30)) -Description 'Disposable AIW107 MSIX trial; restore checkpoint after export'
        $sid = $user.SID.Value
        if ($sid -ceq $operatorSid -or $sid -cnotmatch '\AS-1-5-21-3556347314-2314855617-1438300668-[0-9]+\z') { throw 'Created account identity differs' }
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
        if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -ceq $sid }).Count -ne 0) { throw 'Trial account is an administrator' }
        $account = [ordered]@{schemaVersion='aiw.dev/research-primary-account/v1'; vmId=$uuid; accountName='AiwStandardUser'; accountCreated=$true; userSid=$sid; runNonce=(New-AiwMsixPrimaryNonce); notBeforeFileTime=$before}
        Write-Record 'account.json' $account
        # One exact SYSTEM task removes temporary automatic-sign-in material on
        # logon or at expiry. Credentials are never printed or exported.
        $service = New-Object -ComObject Schedule.Service; $service.Connect(); $folder = $service.GetFolder('\')
        $task = $service.NewTask(0); $task.Principal.UserId='S-1-5-18'; $task.Principal.LogonType=5; $task.Principal.RunLevel=1
        $task.Settings.ExecutionTimeLimit='PT1M'; $task.Settings.DisallowStartIfOnBatteries=$false; $task.Settings.StopIfGoingOnBatteries=$false
        $trigger=$task.Triggers.Create(9); $trigger.UserId=$sid
        $expiry=$task.Triggers.Create(1); $expiry.StartBoundary=[DateTime]::UtcNow.AddMinutes(30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        $action=$task.Actions.Create(0); $action.Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $action.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\AIW-Worker107-Research-r1\worker107-msix.ps1 -Operation ClearLogon'
        $null=$folder.RegisterTaskDefinition('AIW107-ClearLogon-r1',$task,0x12,'S-1-5-18',$null,5,'O:SYG:SYD:P(A;;FA;;;SY)')
        Set-ProtectedAcl $inputRoot $sid
        Set-ProtectedAcl 'C:\AIW-Worker107-UI-r1' $sid
        $winlogon.SetValue('DefaultUserName','AiwStandardUser'); $winlogon.SetValue('DefaultDomainName',$env:COMPUTERNAME)
        $winlogon.SetValue('DefaultPassword',$password); $winlogon.SetValue('AutoLogonCount',1,[Microsoft.Win32.RegistryValueKind]::DWord)
        $winlogon.SetValue('AutoAdminLogon','1')
        Write-Record 'Enroll.result.json' @{account=$account; restartRequired=$true; temporaryAutomaticSignIn=$true; credentialsExported=$false}
    } catch { Write-Record 'Enroll.failure.json' @{error=$_.Exception.Message; recovery='export diagnostics then restore worker107 checkpoint'}; throw }
    finally { $password=$null; if($secure){$secure.Dispose()}; $winlogon.Dispose() }
    Read-Record 'Enroll.result.json' | ConvertTo-Json -Depth 5
    return
}
$account = Read-Record 'account.json'
Assert-OwnedAccount $account
if ($Operation -eq 'ClearLogon') {
    $winlogon = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',$true)
    try {
        if ($winlogon.GetValue('DefaultUserName') -cne 'AiwStandardUser') { throw 'Automatic sign-in owner differs' }
        $winlogon.DeleteValue('DefaultPassword',$false); $winlogon.DeleteValue('AutoLogonCount',$false); $winlogon.SetValue('AutoAdminLogon','0')
    } finally { $winlogon.Dispose() }
    Assert-AutomaticSignInCleared
    if(!(Test-Path -LiteralPath (Join-Path $root 'logon-cleared.json'))) {
        Write-Record 'logon-cleared.json' @{schemaVersion='aiw.dev/worker107-logon-cleared/v1';runNonce=$account.runNonce;userSid=$account.userSid;passwordValuePresent=$false;automaticSignInDisabled=$true;observedUtc=[DateTime]::UtcNow.ToString('o')}
    }
    if ([DateTime]::UtcNow.ToFileTimeUtc() -gt ($account.notBeforeFileTime + 18000000000)) { Disable-LocalUser -SID $account.userSid }
    @{automaticSignInCleared=$true; credentialsExported=$false} | ConvertTo-Json
    return
}
if($Operation -eq 'Prepare') {
    & (Join-Path $root 'worker107-msix.ps1') -Operation ClearLogon | Out-Null
}
if($Operation -in @('Prepare','Control','Trial','Edit','Export')) {
    Assert-AutomaticSignInCleared
    $cleared=Read-Record 'logon-cleared.json'
    if($cleared.runNonce -cne $account.runNonce -or $cleared.userSid -cne $account.userSid -or $cleared.passwordValuePresent -isnot [bool] -or $cleared.passwordValuePresent -or $cleared.automaticSignInDisabled -isnot [bool] -or !$cleared.automaticSignInDisabled){throw 'Measured automatic-sign-in cleanup receipt required'}
}
if ($Operation -eq 'Prepare') {
    Write-Record 'Prepare.started.json' @{startedUtc=[DateTime]::UtcNow.ToString('o')}
    try {
        $sessions = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object {
            (Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid).Sid -ceq $account.userSid
        } | Select-Object -ExpandProperty SessionId -Unique)
        if ($sessions.Count -ne 1 -or $sessions[0] -le 0) { throw 'Actual trial-user interactive Explorer session required' }
        $baseline=Read-Record 'baseline.json'
        $prepared=New-AiwMsixPrimaryPreparation -CreatedAccount $account -SessionId $sessions[0] -SourceImageSha256 $baseline.driverSha256 -NowFileTime ([DateTime]::UtcNow.ToFileTimeUtc())
        if(Test-Path -LiteralPath $preparationPath){throw 'Refuse existing preparation'}
        $acl=[Security.AccessControl.FileSecurity]::new(); $acl.SetAccessRuleProtection($true,$false); $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
        foreach($principal in @('S-1-5-18',$operatorSid)){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($principal),'FullControl','Allow'))}
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($account.userSid),'ReadAndExecute','Allow'))
        $file=[IO.FileStream]::new($preparationPath,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$acl)
        try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($prepared|ConvertTo-Json));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
        Write-Record 'Prepare.result.json' $prepared
    } catch {Write-Record 'Prepare.failure.json' @{error=$_.Exception.Message};throw}
    Read-Record 'Prepare.result.json' | ConvertTo-Json
    return
}
# Long-running controls and lifecycle use the reviewed Scheduler templates; no
# caller-selected executable, script, task name, SID, nonce or command is accepted.
if ($Operation -in @('Control','Trial')) {
    Write-Record "$Operation.started.json" @{startedUtc=[DateTime]::UtcNow.ToString('o'); applicationTrial=($Operation -eq 'Trial')}
    try {
        $prepared=Read-Record 'Prepare.result.json'; $baseline=Read-Record 'baseline.json'
        if ($Operation -eq 'Trial') {
            $control=Read-Record 'Control.result.json'
            if(!$control.passed){throw 'Native WTS control must pass first'}
            Assert-RegularPath $outputRoot
            $archive=Join-Path $root 'control-native'
            if(Test-Path -LiteralPath $archive){throw 'Refuse existing control archive'}
            [IO.Directory]::Move($outputRoot,$archive)
            New-ProtectedDirectory $outputRoot
        }
        $values=@{MODE=$Operation;NONCE=$account.runNonce;TRIAL_SID=$account.userSid;DRIVER_SHA=$baseline.driverSha256;CMD_SHA=$baseline.cmdSha256;PREP_SHA=(Get-FileHash -LiteralPath $preparationPath).Hash.ToLowerInvariant();BASELINE_SHA=(Get-FileHash -LiteralPath (Join-Path $root 'baseline.json')).Hash.ToLowerInvariant();ROOT=('C:\AIW-Task-Primary-'+$Operation+'-'+$account.runNonce)}
        $worker=Get-Content -LiteralPath (Join-Path $root 'worker107-scheduler-worker.ps1.in') -Raw
        $controller=Get-Content -LiteralPath (Join-Path $root 'worker107-scheduler-controller.ps1.in') -Raw
        foreach($key in $values.Keys){$worker=$worker.Replace('@@'+$key+'@@',[string]$values[$key]);$controller=$controller.Replace('@@'+$key+'@@',[string]$values[$key])}
        if($Operation -eq 'Trial') {
            $worker=ConvertTo-LifecycleWorker $worker
            $controller=ConvertTo-LifecycleController $controller
        }
        $controller=$controller.Replace('@@WORKER_B64@@',[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($worker)))
        if($worker.Contains('@@') -or $controller.Contains('@@')){throw 'Unresolved closed template binding'}
        $answer=& ([scriptblock]::Create($controller))
        Write-Record "$Operation.result.json" @{passed=$true; controller=($answer|ConvertFrom-Json); runNonce=$account.runNonce; applicationTrial=($Operation -eq 'Trial')}
    } catch { Write-Record "$Operation.failure.json" @{error=$_.Exception.Message; automaticRetry=$false; restoreAfterExport=$true}; throw }
    Read-Record "$Operation.result.json" | ConvertTo-Json -Depth 12
    return
}
if($Operation -eq 'Edit') {
    if(!(Test-Path -LiteralPath (Join-Path $root 'Trial.started.json')) -or
        (Test-Path -LiteralPath (Join-Path $root 'Trial.result.json')) -or
        (Test-Path -LiteralPath (Join-Path $root 'Trial.failure.json')) -or
        !(Test-Path -LiteralPath 'C:\Users\AiwStandardUser\AppData\Local\AIW\msix-lifecycle\awaiting-edit.json')) {throw 'Live native awaiting-edit stage required'}
    Write-Record 'Edit.started.json' @{startedUtc=[DateTime]::UtcNow.ToString('o');runNonce=$account.runNonce}
    $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
    $task=$service.NewTask(0);$task.Principal.UserId=$account.userSid;$task.Principal.LogonType=3;$task.Principal.RunLevel=0
    $task.Settings.ExecutionTimeLimit='PT2M';$task.Settings.DisallowStartIfOnBatteries=$false;$task.Settings.StopIfGoingOnBatteries=$false
    $action=$task.Actions.Create(0);$action.Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $action.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\AIW-Worker107-UI-r1\worker107-editor.ps1'
    $registered=$folder.RegisterTaskDefinition(('AIW107-Edit-'+$account.runNonce),$task,0x12,$account.userSid,$null,3,'O:SYG:SYD:P(A;;FA;;;SY)')
    if($registered.Definition.Principal.UserId -cne $account.userSid -or $registered.Definition.Principal.LogonType -ne 3 -or $registered.Definition.Principal.RunLevel -ne 0){throw 'Interactive edit task principal differs'}
    $instance=$registered.RunEx($null,0,0,$null)
    Write-Record 'Edit.result.json' @{dispatched=$true;completion='see native lifecycle and ui-edit-result';taskPath=$registered.Path;instanceGuid=$instance.InstanceGuid;runNonce=$account.runNonce}
    Read-Record 'Edit.result.json'|ConvertTo-Json
    return
}
if($Operation -eq 'Export') {
    $failed=$false
    foreach($name in @('Control','Trial')) {
        if(Test-Path -LiteralPath (Join-Path $root "$name.started.json")) {
            $success=Test-Path -LiteralPath (Join-Path $root "$name.result.json")
            $failure=Test-Path -LiteralPath (Join-Path $root "$name.failure.json")
            if(!$success -and !$failure){throw 'Do not export an active native operation'}
            if($failure){$failed=$true}
        }
    }
    $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
    $activeTasks=@()
    foreach($task in $folder.GetTasks(1)) {
        if($task.Name -in @(('AIW-Task-Primary-Control-'+$account.runNonce),('AIW-Task-Primary-Trial-'+$account.runNonce),('AIW107-Edit-'+$account.runNonce))) {
            if($task.GetInstances(0).Count -ne 0){$activeTasks+=$task.Path}
        }
    }
    if(@($activeTasks|Where-Object{$_ -like '\AIW107-Edit-*'}).Count -ne 0){throw 'Wait for the exact edit task to exit before export'}
    if(!$failed -and $activeTasks.Count -ne 0){throw 'Successful export requires no active owned task'}
    $outcome='preparation-or-control-only'
    if($failed){$outcome='failure-cold-recovery';$cleanupClaim='notInferredFromArchive'}
    elseif(Test-Path -LiteralPath (Join-Path $root 'Trial.result.json')) {
        $trial=Read-Record 'Trial.result.json'
        $cleanup=Get-Content -LiteralPath ('C:\AIW-Task-Primary-Trial-'+$account.runNonce+'\cleanup.json') -Raw|ConvertFrom-Json
        $native=Get-Content -LiteralPath (Join-Path $outputRoot 'standard-user-lifecycle\result.json') -Raw|ConvertFrom-Json
        if(!$trial.passed -or !$cleanup.nativeExitConfirmed -or !$cleanup.actionExited -or !$cleanup.taskAbsent -or !$cleanup.instanceAbsent -or !$native.passed -or !$native.jobEmpty){throw 'Successful export requires native terminal and exact cleanup receipts'}
        $outcome='native-lifecycle-passed';$cleanupClaim='seeNativeAndControllerReceipts'
    } else {$cleanupClaim='noLifecycleSuccessClaim'}
    Add-Type -AssemblyName System.IO.Compression
    $zipPath=Join-Path $root 'evidence.zip'
    if(Test-Path -LiteralPath $zipPath){throw 'Preserve existing evidence export; use retained archive'}
    $directories=@($outputRoot,('C:\AIW-Task-Primary-Control-'+$account.runNonce),('C:\AIW-Task-Primary-Trial-'+$account.runNonce),('C:\AIW-Msix-Primary-Control-Controller-r1'),('C:\AIW-Msix-Primary-Trial-Controller-r1'),(Join-Path $root 'control-native'))
    $files=@(Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Extension -ceq '.json' })
    $entries=@($files | ForEach-Object { [pscustomobject]@{file=$_;name=('worker/'+$_.Name)} })
    for($index=0;$index -lt $directories.Count;$index++) {
        $directory=$directories[$index]
        if(!(Test-Path -LiteralPath $directory)){continue}
        Assert-RegularPath $directory
        # Stop on reparse entries before descending. The user-writable evidence
        # source is exported only after native terminal completion/cleanup.
        $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($directory)
        while($pending.Count -gt 0) {
            $next=$pending.Dequeue()
            foreach($item in Get-ChildItem -LiteralPath $next -Force) {
                Assert-RegularPath $item.FullName
                if($item.PSIsContainer){$pending.Enqueue($item.FullName)}else{
                    $relative=$item.FullName.Substring($directory.Length+1).Replace('\','/')
                    $entries += [pscustomobject]@{file=$item;name=($index.ToString()+'/'+$relative)}
                }
                if($pending.Count+$entries.Count -gt 1024){throw 'Export entry bound exceeded'}
            }
        }
    }
    $total=[long]0;foreach($entry in $entries){$total+=$entry.file.Length;if($entry.file.Length -gt 8388608 -or $total -gt 33554432){throw 'Export size bound exceeded'}}
    $stream=[IO.File]::Open($zipPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {foreach($entry in $entries){
            $target=$zip.CreateEntry($entry.name,[IO.Compression.CompressionLevel]::Optimal)
            $destination=$target.Open();$source=[IO.File]::Open($entry.file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{$source.CopyTo($destination)}finally{$source.Dispose();$destination.Dispose()}
        }} finally {$zip.Dispose()}
        $stream.Flush($true)
    } finally {$stream.Dispose()}
    if((Get-Item -LiteralPath $zipPath).Length -gt 8388608){throw 'Compressed evidence exceeds transport bound; preserve archive'}
    [ordered]@{schemaVersion='aiw.dev/worker107-msix-export/v1';outcome=$outcome;cleanupClaim=$cleanupClaim;activeOwnedTasks=$activeTasks;sha256=(Get-FileHash -LiteralPath $zipPath).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $zipPath).Length;fileCount=$entries.Count;archivePath=$zipPath;credentialsIncluded=$false}|ConvertTo-Json -Compress
    return
}
