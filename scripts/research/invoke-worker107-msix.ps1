#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Connect','Stage','Enroll','ClearLogon','Prepare','Control','Trial','Edit','Status','Export','Collect','Restart')][string]$Operation,
    [string]$PayloadDirectory,
    [string]$EvidenceDirectory,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$ApprovedManifestSha256,
    [ValidatePattern('\A[0-9a-f]{40}\z')][string]$ApprovedSourceCommit
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$credentialPath=Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml'
$session=$null;$credential=$null
try {
    # Operator-observed certificate from the exact VM107 Proxmox console.
    # This probe precedes credential access; the subsequent WSMan connection is
    # a separate TLS channel on the operator-trusted lab network, not a channel pin.
    $expectedCertificate='BC14DCC4E37F83161EBB55AF8624E36A79E19256'
    $tcp=[Net.Sockets.TcpClient]::new()
    $tls=$null
    try {
        if(!$tcp.ConnectAsync('192.168.1.174',5986).Wait(10000)){throw 'VM107 HTTPS connection timed out'}
        $tls=[Net.Security.SslStream]::new($tcp.GetStream(),$false,([Net.Security.RemoteCertificateValidationCallback]{param($sender,$certificate,$chain,$errors) $certificate.GetCertHashString() -ceq $expectedCertificate}))
        $tls.ReadTimeout=10000;$tls.WriteTimeout=10000
        $tls.AuthenticateAsClient('192.168.1.174')
        if($tls.RemoteCertificate.GetCertHashString() -cne $expectedCertificate){throw 'VM107 console certificate differs'}
    } finally {if($tls){$tls.Dispose()};$tcp.Dispose()}
    $storedCredential=Import-Clixml -LiteralPath $credentialPath
    $credential=[pscredential]::new('labadmin',$storedCredential.Password)
    $storedCredential=$null
    $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName Microsoft.PowerShell -SessionOption (New-PSSessionOption -SkipCACheck -OpenTimeout 15000 -OperationTimeout 60000)
    $identity=Invoke-Command -Session $session -ScriptBlock {
        $ErrorActionPreference='Stop'
        $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
        if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'STOP: Exact VM107 UUID required'}
        $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
        if($actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Pinned elevated labadmin operator required'}
        [pscustomobject]@{workerVmId=107;uuid=$uuid;actorSid=$actor.User.Value;computerName=$env:COMPUTERNAME;administrator=$true}
    }
    if($Operation -eq 'Connect'){$identity|ConvertTo-Json;return}
    if($Operation -eq 'Restart'){
        Invoke-Command -Session $session -ScriptBlock {
            $root='C:\AIW-Worker107-Research-r1'
            $account=Get-Content -LiteralPath ($root+'\account.json') -Raw|ConvertFrom-Json
            $enrolled=Get-Content -LiteralPath ($root+'\Enroll.result.json') -Raw|ConvertFrom-Json
            if(!$enrolled.restartRequired -or $account.vmId -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $account.runNonce -cne $enrolled.account.runNonce){throw 'Run-owned enrollment required before restart'}
            $marker=$root+'\Restart.request.json'
            $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{operation='Restart';runNonce=$account.runNonce;requestedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json))
            $file=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
            Restart-Computer -Force
        }
        return
    }
    if($Operation -eq 'Stage') {
        if(!$PayloadDirectory -or !$ApprovedManifestSha256 -or !$ApprovedSourceCommit){throw 'Reviewed payload directory and independently approved manifest/source identities required'}
        if((Get-FileHash -LiteralPath (Join-Path $PayloadDirectory 'bundle.json')).Hash.ToLowerInvariant() -cne $ApprovedManifestSha256){throw 'Independently approved manifest identity differs'}
        $manifest=Get-Content -LiteralPath (Join-Path $PayloadDirectory 'bundle.json') -Raw|ConvertFrom-Json
        if($manifest.sourceCommit -cne $ApprovedSourceCommit -or $manifest.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $manifest.schemaVersion -cne 'aiw.dev/worker107-msix-bundle/v1' -or $manifest.driverSha256 -cne '05f2ff8638adb3a156696de60bb1fd23341ee201a497c105359fa926d6d0e812'){throw 'Reviewed bundle source/worker/driver identity differs'}
        $expected=@('application.msix','assembly.json','signing.json','msix_standard_user_lifecycle.exe','worker107-msix.ps1','worker107-msix-templates.ps1','worker107-scheduler-controller.ps1.in','worker107-scheduler-worker.ps1.in','msix-primary-preparation.ps1','worker107-editor.ps1','worker107-editor-input.cs','research_msix_native.cs','research_msix_interactive.cs')|Sort-Object
        if((@($manifest.files|ForEach-Object{$_.name}|Sort-Object)-join '|') -cne ($expected-join '|')){throw 'Closed payload file set differs'}
        foreach($entry in $manifest.files) {
            if($entry.name -cnotmatch '\A[a-zA-Z0-9_.-]+\z' -or (Get-FileHash -LiteralPath (Join-Path $PayloadDirectory $entry.name)).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'Payload content identity differs'}
        }
        Invoke-Command -Session $session -ScriptBlock {
            if(Test-Path -LiteralPath 'C:\AIW-Worker107-Intake-r1'){throw 'Preserve existing intake; no automatic retry'}
            $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-21-3556347314-2314855617-1438300668-1001'))
            foreach($sid in @('S-1-5-18','S-1-5-21-3556347314-2314855617-1438300668-1001')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
            [IO.Directory]::CreateDirectory('C:\AIW-Worker107-Intake-r1',$acl)|Out-Null
        }
        foreach($name in @('bundle.json')+@($manifest.files|ForEach-Object{$_.name})){
            Copy-Item -LiteralPath (Join-Path $PayloadDirectory $name) -Destination ('C:\AIW-Worker107-Intake-r1\'+$name) -ToSession $session
        }
        $remoteManifest=Invoke-Command -Session $session -ScriptBlock {(Get-FileHash -LiteralPath 'C:\AIW-Worker107-Intake-r1\bundle.json').Hash.ToLowerInvariant()}
        if($remoteManifest -cne $ApprovedManifestSha256){throw 'Remote manifest transfer differs'}
        Invoke-Command -Session $session -ScriptBlock {
            $ErrorActionPreference='Stop';$root='C:\AIW-Worker107-Intake-r1';$manifest=Get-Content -LiteralPath ($root+'\bundle.json') -Raw|ConvertFrom-Json
            foreach($entry in $manifest.files){if((Get-FileHash -LiteralPath (Join-Path $root $entry.name)).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'Transferred source file differs before SYSTEM dispatch'}}
        }
    }
    if($Operation -eq 'Status') {
        $status=Invoke-Command -Session $session -ScriptBlock {
            $ErrorActionPreference='Stop';$intake='C:\AIW-Worker107-Intake-r1'
            $operations=[ordered]@{}
            foreach($op in @('Stage','Enroll','ClearLogon','Prepare','Control','Trial','Edit','Export')){
                $path=Join-Path $intake ($op+'.transport-result.json')
                if(Test-Path -LiteralPath $path){$operations[$op]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
                elseif(Test-Path -LiteralPath (Join-Path $intake ($op+'.request.json'))){$operations[$op]=@{completed=$false;automaticRetry=$false}}
            }
            $worker=$null
            if(Test-Path -LiteralPath 'C:\AIW-Worker107-Research-r1\Stage.result.json'){
                $lines=& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -ExecutionPolicy Bypass -File 'C:\AIW-Worker107-Research-r1\worker107-msix.ps1' -Operation Status
                if($LASTEXITCODE -ne 0){throw 'Worker status read failed'}
                $worker=($lines -join "`n")|ConvertFrom-Json
            }
            [pscustomobject]@{operations=$operations;worker=$worker}
        }
        $status|ConvertTo-Json -Depth 18
        return
    }
    if($Operation -eq 'Collect') {
        if(!$EvidenceDirectory -or (Test-Path -LiteralPath $EvidenceDirectory)){throw 'Fresh external evidence directory required'}
        $export=Invoke-Command -Session $session -ScriptBlock {
            $r=Get-Content -LiteralPath 'C:\AIW-Worker107-Intake-r1\Export.transport-result.json' -Raw|ConvertFrom-Json
            if(!$r.completed -or $r.exitCode -ne 0){throw 'Export must complete successfully'}
            $value=Get-Content -LiteralPath 'C:\AIW-Worker107-Intake-r1\Export.stdout.json' -Raw|ConvertFrom-Json
            if($value.schemaVersion -cne 'aiw.dev/worker107-msix-export/v1' -or $value.archivePath -cne 'C:\AIW-Worker107-Research-r1\evidence.zip' -or $value.credentialsIncluded -isnot [bool] -or $value.credentialsIncluded){throw 'Fixed evidence export required'}
            $value
        }
        New-Item -ItemType Directory -Path $EvidenceDirectory|Out-Null
        $zip=Join-Path $EvidenceDirectory 'evidence.zip'
        Copy-Item -FromSession $session -LiteralPath 'C:\AIW-Worker107-Research-r1\evidence.zip' -Destination $zip
        if((Get-FileHash -LiteralPath $zip).Hash.ToLowerInvariant() -cne $export.sha256 -or (Get-Item -LiteralPath $zip).Length -ne $export.bytes){throw 'Export transfer hash/length differs'}
        $export|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'export.json')
        $export|Select-Object outcome,sha256,bytes,fileCount,cleanupClaim|ConvertTo-Json
        return
    }
    $request=Invoke-Command -Session $session -ArgumentList $Operation -ScriptBlock {
        param([ValidateSet('Stage','Enroll','ClearLogon','Prepare','Control','Trial','Edit','Export')][string]$Op)
        $ErrorActionPreference='Stop';$intake='C:\AIW-Worker107-Intake-r1';$name='AIW107-Transport-'+$Op+'-r1'
        $marker=Join-Path $intake ($Op+'.request.json')
        if(Test-Path -LiteralPath $marker){throw 'Preserve existing operation request; inspect status instead of repeating'}
        $source=Join-Path $intake 'worker107-msix.ps1'
        if((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Regular intake source required'}
        $taskSource=@'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$intake='C:\AIW-Worker107-Intake-r1'
$exitCode=0;$errorText=$null
try {
 if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Wrong worker UUID'}
 $lines=& ($intake+'\worker107-msix.ps1') -Operation @@OP@@
 [IO.File]::WriteAllText(($intake+'\@@OP@@.stdout.json'),($lines -join "`n"),[Text.UTF8Encoding]::new($false))
} catch {$exitCode=1;$errorText=$_.Exception.ToString();[IO.File]::WriteAllText(($intake+'\@@OP@@.stderr.txt'),($_|Out-String),[Text.UTF8Encoding]::new($false))}
$record=@{completed=$true;exitCode=$exitCode;error=$errorText;operation='@@OP@@';completedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json
$f=[IO.File]::Open(($intake+'\@@OP@@.transport-result.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes($record);$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
exit $exitCode
'@
        $taskSource=$taskSource.Replace('@@OP@@',$Op)
        $taskFile=Join-Path $intake ($Op+'.task.ps1')
        [IO.File]::WriteAllText($taskFile,$taskSource,[Text.UTF8Encoding]::new($false))
        $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
        if(@($folder.GetTasks(1)|Where-Object Name -CEQ $name).Count -ne 0){throw 'Fresh transport task required'}
        $definition=$service.NewTask(0);$definition.Principal.UserId='S-1-5-18';$definition.Principal.LogonType=5;$definition.Principal.RunLevel=1
        $definition.Settings.ExecutionTimeLimit=$(if($Op -eq 'Trial'){'PT26M'}else{'PT5M'})
        $definition.Settings.DisallowStartIfOnBatteries=$false;$definition.Settings.StopIfGoingOnBatteries=$false
        $action=$definition.Actions.Create(0);$action.Path='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $action.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+$taskFile
        $sddl='O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-3556347314-2314855617-1438300668-1001)'
        $registered=$folder.RegisterTaskDefinition($name,$definition,0x12,'S-1-5-18',$null,5,$sddl)
        $registeredUser=$registered.Definition.Principal.UserId
        $registeredSid=if($registeredUser -match '\AS-1-'){[Security.Principal.SecurityIdentifier]::new($registeredUser).Value}else{([Security.Principal.NTAccount]::new($registeredUser)).Translate([Security.Principal.SecurityIdentifier]).Value}
        if($registeredSid -cne 'S-1-5-18' -or $registered.Definition.Principal.LogonType -ne 5 -or $registered.Definition.Principal.RunLevel -ne 1){throw 'Registered SYSTEM transport identity differs'}
        $request=@{operation=$Op;task=$registered.Path;sourceSha256=(Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant();requestedUtc=[DateTime]::UtcNow.ToString('o')}
        [IO.File]::WriteAllText($marker,($request|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        $instance=$registered.RunEx($null,0,0,$null)
        [pscustomobject]@{dispatched=$true;operation=$Op;task=$registered.Path;instanceGuid=$instance.InstanceGuid;workerVmId=107}
    }
    $request|ConvertTo-Json
} finally {if($session){Remove-PSSession $session};$credential=$null}
