#Requires -Version 7.6
#Requires -PSEdition Core
# Closed, fresh VM107 fixture operations. Never installs or launches an app.
param(
 [Parameter(Mandatory)][ValidateSet('CreateRawWithNamedStream','ClearNamedStream','AddPartialCache','QueuedConsumerRegression')][string]$Mode,
 [Parameter(Mandatory)][string]$Workspace,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestFileSha256,
 [Parameter(Mandatory)][string]$TransportPath,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$TransportSha256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$ProgressPreference='SilentlyContinue'
if($PSVersionTable.PSVersion -lt [version]'7.6' -or $PSHOME -ine 'C:\Program Files\PowerShell\7' -or [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ine 'C:\Program Files\PowerShell\7\pwsh.exe'){throw 'Installed stable Core 7.6+ host required'}
$normalized=[IO.Path]::GetFullPath($Workspace)
if($normalized -cnotmatch '\AC:\\AIW-Resume-20261021\\powershell76-native-[0-9]+\\workspace\z'){throw 'Fresh Core native evidence root required'}
$transportHold=$null;$requestHold=$null;$session=$null;$credential=$null
try {
 $transportHold=[IO.File]::Open($TransportPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($transportHold)).ToLowerInvariant() -cne $TransportSha256){throw 'Compiled transport source differs'}
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($TransportPath,[ref]$tokens,[ref]$errors)
 if($errors.Count -ne 0){throw 'Compiled transport did not parse'}
 $assignments=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$runtimeProof'},$true))
 if($assignments.Count -ne 1){throw 'One fixed runtime proof required'}
 $blocks=@($assignments[0].Right.FindAll({param($n) $n -is [Management.Automation.Language.ScriptBlockExpressionAst]},$false))
 if($blocks.Count -ne 1){throw 'One literal runtime observer required'}
 $literal=$blocks[0].ScriptBlock.Extent.Text
 if(!$literal.StartsWith('{') -or !$literal.EndsWith('}')){throw 'Literal runtime proof required'}
 $runtimeProof=[scriptblock]::Create($literal.Substring(1,$literal.Length-2))
 foreach($name in @('Assert-AiwRuntimeBinding','Assert-AiwWsmanBinding')){
  $functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
  if($functions.Count -ne 1){throw 'One fixed binding consumer required'}
  . ([scriptblock]::Create($functions[0].Extent.Text))
 }
 $hostRuntime=& $runtimeProof Direct
 # Extract the actual production consumer for one separately labeled injected
 # queued-state regression. Do not maintain a second copy of its implementation.
 $branches=@($ast.FindAll({param($n)
  if($n -isnot [Management.Automation.Language.IfStatementAst]){return $false}
  @($n.Clauses|Where-Object {$_.Item1.Extent.Text -cmatch '\$Operation\s+-eq\s+''Collect'''}).Count -eq 1
 },$true))
 if($branches.Count -ne 1){throw 'One fixed Collect branch required'}
 $clause=@($branches[0].Clauses|Where-Object {$_.Item1.Extent.Text -cmatch '\$Operation\s+-eq\s+''Collect'''})[0]
 $commands=@($clause.Item2.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Invoke-Command'},$true))
 if($commands.Count -ne 1){throw 'One Collect Invoke-Command required'}
 $collectBlocks=@($commands[0].CommandElements|Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]})
 if($collectBlocks.Count -ne 1){throw 'One literal Collect body required'}
 $literal=$collectBlocks[0].ScriptBlock.Extent.Text
 if(!$literal.StartsWith('{') -or !$literal.EndsWith('}')){throw 'Literal Collect body required'}
 $collectSource=$literal.Substring(1,$literal.Length-2)
 $requestPath=Join-Path $Workspace 'tools\request.json'
 $requestHold=[IO.File]::Open($requestPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($requestHold)).ToLowerInvariant() -cne $RequestFileSha256){throw 'Bounded fixture host request differs'}
 $request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
 if($request.runId -cnotmatch '\Amsix-core76-bounded-[0-9]+\z' -or $request.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Fresh bounded VM107 request required'}
 if(!$request.powerShellRuntime -or $request.powerShellRuntime.endpoint -cne 'PowerShell.7.6' -or !$request.powerShellRuntime.host -or !$request.powerShellRuntime.worker -or !$request.powerShellRuntime.wsman){throw 'Exact approved Core runtime binding required'}
 Assert-AiwRuntimeBinding $hostRuntime $request.powerShellRuntime.host
 $stored=Import-Clixml -LiteralPath (Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml')
 $credential=[pscredential]::new('labadmin',$stored.Password);$stored=$null
 $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName PowerShell.7.6 -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
 $remote=Invoke-Command -Session $session -ScriptBlock $runtimeProof -ArgumentList 'WSMan',$runtimeProof.ToString()
 Assert-AiwRuntimeBinding $remote.worker $request.powerShellRuntime.worker
 Assert-AiwWsmanBinding $remote.wsman $request.powerShellRuntime.wsman
 Invoke-Command -Session $session -ArgumentList $Mode,$request.runId,$request.nonce,$RequestSha256,$RequestFileSha256,$collectSource -ScriptBlock {
  param($mode,$runId,$nonce,$requestSha,$requestFileSha,$collectSource)
  $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
  if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSHOME -ine 'C:\Program Files\PowerShell\7' -or $PSSenderInfo.ConfigurationName -cne 'PowerShell.7.6' -or [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ine 'C:\Windows\System32\wsmprovhost.exe'){throw 'Exact approved Core WSMan host required'}
  $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
  $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
  if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Exact elevated VM107 operator required'}
  $root='C:\ProgramData\AIW\MsixWorker\'+$runId
  if((Get-FileHash -LiteralPath (Join-Path $root 'request.json')).Hash.ToLowerInvariant() -cne $requestFileSha){throw 'Exact guest request required'}
  if(Test-Path -LiteralPath (Join-Path $root 'run-dispatch.json')){throw 'Bounded fixture must not follow an application dispatch'}
  $account=Get-Content -LiteralPath (Join-Path $root 'account.json') -Raw|ConvertFrom-Json
  $control=Get-Content -LiteralPath (Join-Path $root 'control-result.json') -Raw|ConvertFrom-Json
  if($account.runNonce -cne $nonce -or $control.nonce -cne $nonce -or $control.requestSha256 -cne $requestSha -or !$control.passed -or $control.observedExitCode -ne 42 -or $control.userSid -cne $account.userSid){throw 'Same-run native control required before fixture setup'}
  if($mode -ceq 'QueuedConsumerRegression'){
   # Isolate the task branch of the production OR guard. An unrelated real
   # agent/editor process must not make a broken Queued assertion pass.
   # No task is registered or dispatched; no process is started or stopped.
   function Get-ScheduledTask { [pscustomobject]@{TaskName='AIW-Msix-acceptance-queued';State='Queued'} }
   function Get-Process { param([string[]]$Name,$ErrorAction) @() }
   $errorText=$null
   try {$null=& ([scriptblock]::Create($collectSource)) $root $nonce}catch{$errorText=$_.Exception.Message}
   if($errorText -cne 'Worker running or queued; preserve its lease and evidence'){throw 'Production Collect accepted queued work or failed for another reason'}
   return @{mode=$mode;nonce=$nonce;queuedRejected=$true;processObservationInjectedEmpty=$true;nativeSchedulerQueueObserved=$false;applicationExecuted=$false;workerUuid=$uuid}
  }
  $user=Get-LocalUser -Name AiwStandardUser
  $profiles=@(Get-CimInstance Win32_UserProfile|Where-Object SID -CEQ $account.userSid)
  if($user.SID.Value -cne $account.userSid -or $profiles.Count -ne 1 -or !$profiles[0].Loaded){throw 'Exact loaded run-owned profile required'}
  $source=Join-Path $profiles[0].LocalPath ('AppData\Local\AIW\msix-'+$nonce)
  $document=Join-Path $source 'msix-lifecycle\document.txt'
  function Write-New([string]$path,[byte[]]$bytes){
   $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  }
  $utf8=[Text.UTF8Encoding]::new($false)
  $controlTaskProof=$null
  if($mode -ceq 'CreateRawWithNamedStream'){
   # The native worker can publish its terminal record shortly before Task
   # Scheduler finishes its wrapper. Poll only read-only observations; never
   # accept a queued/running task failure as the named-stream export regression.
   $terminal=Get-Content -LiteralPath (Join-Path $root 'control-transport.json') -Raw|ConvertFrom-Json
   if($terminal.nonce -cne $nonce -or $terminal.operation -cne 'control' -or $terminal.completed -ne $true -or $terminal.exitCode -ne 0){throw 'Exact successful native Control transport terminal required'}
   $deadline=[DateTime]::UtcNow.AddSeconds(30)
   do {
    $task=@(Get-ScheduledTask -TaskName ('AIW-Msix-control-'+$runId) -ErrorAction Stop)
    if($task.Count -ne 1){throw 'Exact native Control task required'}
    $info=$task[0]|Get-ScheduledTaskInfo -ErrorAction Stop
    $active=@(Get-ScheduledTask|Where-Object {$_.TaskName -like 'AIW-Msix-*' -and $_.State -in @('Running','Queued')})
    $processes=@(Get-Process -Name 'agent','notepad++' -ErrorAction SilentlyContinue)
    if($task[0].State -eq 'Ready' -and $info.LastTaskResult -eq 0 -and $active.Count -eq 0 -and $processes.Count -eq 0){break}
    if([DateTime]::UtcNow -ge $deadline){throw 'Native Control task/process quiescence not established before fixture creation'}
    Start-Sleep -Milliseconds 250
   }while($true)
   $controlTaskProof=@{taskName=$task[0].TaskName;state=[string]$task[0].State;lastTaskResult=$info.LastTaskResult;activeProjectTasks=$active.Count;activeApplicationOrAgentProcesses=$processes.Count;completed=$true;exitCode=$terminal.exitCode;nonce=$nonce}
   if((Test-Path -LiteralPath $source) -or (Test-Path -LiteralPath (Join-Path $root 'evidence')) -or (Test-Path -LiteralPath (Join-Path $root 'failed-evidence'))){throw 'Fresh no-copy fixture required'}
   $null=New-Item -ItemType Directory -Path (Join-Path $source 'msix-lifecycle')
   Write-New (Join-Path $source 'child-started.json') $utf8.GetBytes((@{acceptanceFixture=$true;nonce=$nonce;applicationExecuted=$false}|ConvertTo-Json -Compress))
   Write-New $document $utf8.GetBytes("AIW Core76 bounded raw evidence acceptance`r`n")
   Write-New (Join-Path $source 'msix-lifecycle\probe.json') $utf8.GetBytes('{"acceptanceFixture":true,"applicationExecuted":false}')
   Set-Content -LiteralPath $document -Stream AIWAcceptance -Value 'bounded export failure injection' -Encoding ASCII
  } elseif($mode -ceq 'ClearNamedStream'){
   if([IO.File]::ReadAllText($document) -cne "AIW Core76 bounded raw evidence acceptance`r`n" -or @(Get-Item -LiteralPath $document -Stream AIWAcceptance).Count -ne 1){throw 'Exact blocked fixture required'}
   Remove-Item -LiteralPath $document -Stream AIWAcceptance
  } elseif($mode -ceq 'AddPartialCache'){
   if(Test-Path -LiteralPath (Join-Path $root 'evidence')){throw 'Fresh partial controller cache required'}
   if([IO.File]::ReadAllText($document) -cne "AIW Core76 bounded raw evidence acceptance`r`n"){throw 'Original fixture bytes changed'}
   $null=New-Item -ItemType Directory -Path (Join-Path $root 'evidence\msix-lifecycle')
   Write-New (Join-Path $root 'evidence\msix-lifecycle\document.txt') $utf8.GetBytes('deliberately incomplete cached copy')
  } else {throw 'Unsupported closed fixture mode'}
  @{mode=$mode;nonce=$nonce;workerUuid=$uuid;userSid=$account.userSid;rawFiles=@(Get-ChildItem -LiteralPath $source -File -Recurse).Count;applicationExecuted=$false;controlExitCode=42;controlTaskProof=$controlTaskProof}
 }|ConvertTo-Json -Depth 8 -Compress
}finally{
 if($session){Remove-PSSession $session}
 $credential=$null
 if($requestHold){$requestHold.Dispose()}
 if($transportHold){$transportHold.Dispose()}
}
