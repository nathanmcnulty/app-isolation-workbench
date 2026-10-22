# Fixed project cmd/exit-42 control. Does not create a user or install an app.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$operator='S-1-5-21-3849540285-1795134874-2442050430-1006'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $operator){throw 'Wrong worker administrator'}
$stage='C:\AIW-Worker-Setup\msix-vm106-staging\scheduler-control-r1'
$taskName='AIW-VM106-Scheduler-Control-20261021'
$powershell='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Existing control task; retain and inspect'}
foreach($path in @('C:\AIW-Worker-Setup','C:\AIW-Worker-Setup\msix-vm106-staging',$stage)){
    $item=Get-Item -LiteralPath $path -Force
    if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected stage path'}
}
$acl=Get-Acl -LiteralPath $stage
if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $operator){throw 'Unprotected stage'}
foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($operator,'S-1-5-18')){throw 'Unexpected stage ACL'}
}
foreach($name in @('worker-process.json','controller-ack','result.json','failure.json','controller-result.json')){
    if(Test-Path -LiteralPath (Join-Path $stage $name)){throw 'Control stage already used; no retry'}
}
$heldFiles=@();$process=$null;$verifiedProcess=$false;$registered=$false;$operation=$null;$cleanupErrors=@();$passed=$false;$workerExited=$false
try {
    foreach($entry in @(@{name='control.ps1';hash='ac88b12c89951978335877e0e274a9c6908b4a2ec8f405733d5437932ec4a2e1'},@{name='worker.ps1';hash='fe3300fd1df86c1aaea1a933fcf2a099c5462ab71bd4f73f91d125674aedab3b'})){
        $path=Join-Path $stage $entry.name
        if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse control file'}
        $heldFiles+= [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.hash){throw 'Control source hash differs'}
    }
    $action=New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$stage+'\worker.ps1"')
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered=$true
    Start-ScheduledTask -TaskName $taskName
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath (Join-Path $stage 'worker-process.json'))){
        if($timer.Elapsed.TotalSeconds -gt 30){throw 'Scheduled worker identity deadline'}
        Start-Sleep -Milliseconds 100
    }
    $identity=Get-Content -LiteralPath (Join-Path $stage 'worker-process.json') -Raw|ConvertFrom-Json
    $process=[Diagnostics.Process]::GetProcessById([int]$identity.pid)
    $handle=$process.Handle
    if($process.HasExited -or $process.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $identity.startFileTime -or
       $process.SessionId -ne 0 -or $process.MainModule.FileName -ine $powershell -or $identity.image -ine $powershell){throw 'Exact scheduled process differs'}
    $owner=Invoke-CimMethod -InputObject (Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)") -MethodName GetOwnerSid
    if($owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18' -or $process.HasExited){throw 'Scheduled process owner differs'}
    $verifiedProcess=$true
    $ack=[IO.File]::Open((Join-Path $stage 'controller-ack'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$ack.Dispose()
    if(!$process.WaitForExit(60000)){throw 'Exact scheduled worker deadline'}
    $workerExited=$true
    if($process.ExitCode -ne 0){throw 'Scheduled worker failed; inspect retained failure receipt'}
    $result=Get-Content -LiteralPath (Join-Path $stage 'result.json') -Raw|ConvertFrom-Json
    if(!$result.controlOnly -or !$result.cleanupConfirmed -or !$result.jobEmpty -or $result.exitCode -ne 42){throw 'Control acceptance differs'}
    $timer.Restart()
    while((Get-ScheduledTask -TaskName $taskName).State -eq 'Running'){
        if($timer.Elapsed.TotalSeconds -gt 5){throw 'Scheduler completion state deadline'}
        Start-Sleep -Milliseconds 100
    }
    $taskInfo=Get-ScheduledTaskInfo -TaskName $taskName
    if($taskInfo.LastTaskResult -ne 0){throw 'Scheduler result differs'}
    $passed=$true
} catch {$operation=$_} finally {
    try {
        if($verifiedProcess -and !$process.HasExited){$process.Kill();if(!$process.WaitForExit(5000)){throw 'Exact worker cleanup unconfirmed'};$workerExited=$true}
    } catch {$cleanupErrors += $_.Exception}
    # Task cleanup is independent of exact-process termination and is always
    # attempted even if that handle could not be terminated or waited on.
    try {
        if($registered){
            Stop-ScheduledTask -TaskName $taskName
            if((Get-ScheduledTask -TaskName $taskName).State -eq 'Running'){throw 'Scheduled task still running'}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Task cleanup unconfirmed'}
        }
    } catch {$cleanupErrors += $_.Exception}
    foreach($file in $heldFiles){$file.Dispose()}
    if($process){$process.Dispose()}
}
$receipt=[ordered]@{passed=($passed -and !$operation -and $cleanupErrors.Count -eq 0);taskAbsent=!(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue);heldWorkerExited=$workerExited;operationError=if($operation){$operation.Exception.ToString()}else{$null};cleanupErrors=@($cleanupErrors|ForEach-Object{$_.ToString()});applicationTrialStarted=$false;isolation='notMeasured'}
$receipt|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $stage 'controller-result.json') -Encoding UTF8
if(!$receipt.passed){throw ($receipt|ConvertTo-Json -Depth 5 -Compress)}
$receipt|ConvertTo-Json -Depth 5 -Compress
