#requires -Version 5.1
# Explicit opt-in live VM107 acceptance fixtures; never application execution.
param(
 [Parameter(Mandatory)][ValidateSet('CreateRawWithNamedStream','AddNamedStream','ClearNamedStream','AddPartialCache')][string]$Mode,
 [Parameter(Mandatory)][string]$Workspace,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$RequestFileSha256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$ProgressPreference='SilentlyContinue'
$requestPath=Join-Path $Workspace 'tools\request.json'
if((Get-FileHash -LiteralPath $requestPath).Hash.ToLowerInvariant() -cne $RequestFileSha256){throw 'Bounded fixture host request differs'}
$request=Get-Content -LiteralPath $requestPath -Raw|ConvertFrom-Json
if($request.runId -cnotmatch '\Amsix-bounded-[0-9]+\z' -or $request.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Bounded VM107 request required'}
$stored=Import-Clixml -LiteralPath (Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml')
$credential=[pscredential]::new('labadmin',$stored.Password);$stored=$null;$session=$null
try {
 $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName Microsoft.PowerShell -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
 Invoke-Command -Session $session -ArgumentList $Mode,$request.runId,$request.nonce,$RequestSha256,$RequestFileSha256 -ScriptBlock {
  param($mode,$runId,$nonce,$requestSha,$requestFileSha)
  $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
  $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
  $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
  if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Exact elevated VM107 operator required'}
  $root='C:\ProgramData\AIW\MsixWorker\'+$runId
  if((Get-FileHash -LiteralPath (Join-Path $root 'request.json')).Hash.ToLowerInvariant() -cne $requestFileSha){throw 'Exact guest request required'}
  if(Test-Path -LiteralPath (Join-Path $root 'run-dispatch.json')){throw 'Bounded fixture must not follow an application dispatch'}
  $account=Get-Content -LiteralPath (Join-Path $root 'account.json') -Raw|ConvertFrom-Json
  $control=Get-Content -LiteralPath (Join-Path $root 'control-result.json') -Raw|ConvertFrom-Json
  if($account.runNonce -cne $nonce -or $control.nonce -cne $nonce -or $control.requestSha256 -cne $requestSha -or !$control.passed -or $control.observedExitCode -ne 42 -or $control.userSid -cne $account.userSid){throw 'Same-run native control required before fixture setup'}
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
  if($mode -eq 'CreateRawWithNamedStream'){
   if((Test-Path -LiteralPath $source) -or (Test-Path -LiteralPath (Join-Path $root 'evidence')) -or (Test-Path -LiteralPath (Join-Path $root 'failed-evidence'))){throw 'Fresh no-copy acceptance fixture required'}
   $null=New-Item -ItemType Directory -Path (Join-Path $source 'msix-lifecycle')
   Write-New (Join-Path $source 'child-started.json') $utf8.GetBytes((@{acceptanceFixture=$true;nonce=$nonce;applicationExecuted=$false}|ConvertTo-Json -Compress))
   Write-New $document $utf8.GetBytes("AIW bounded raw evidence acceptance`r`n")
   Write-New (Join-Path $source 'msix-lifecycle\probe.json') $utf8.GetBytes('{"acceptanceFixture":true,"applicationExecuted":false}')
   Set-Content -LiteralPath $document -Stream AIWAcceptance -Value 'bounded export failure injection' -Encoding ASCII
  } elseif($mode -eq 'AddNamedStream'){
   if((Test-Path -LiteralPath (Join-Path $root 'evidence')) -or @(Get-ChildItem -LiteralPath $source -File -Recurse).Count -ne 3 -or [IO.File]::ReadAllText($document) -cne "AIW bounded raw evidence acceptance`r`n" -or [IO.File]::ReadAllText((Join-Path $source 'msix-lifecycle\probe.json')) -cne '{"acceptanceFixture":true,"applicationExecuted":false}' -or (Get-Content -LiteralPath (Join-Path $source 'child-started.json') -Raw|ConvertFrom-Json).nonce -cne $nonce){throw 'Exact partial fixture required'}
   if(@(Get-Item -LiteralPath $document -Stream *|Where-Object Stream -CNE ':$DATA').Count -ne 0){throw 'Fixture stream already exists'}
   Set-Content -LiteralPath $document -Stream AIWAcceptance -Value 'bounded export failure injection' -Encoding ASCII
  } elseif($mode -eq 'ClearNamedStream'){
   if(!(Test-Path -LiteralPath $document)){throw 'Retained fixture missing'}
   Remove-Item -LiteralPath $document -Stream AIWAcceptance
  } elseif($mode -eq 'AddPartialCache'){
   if(Test-Path -LiteralPath (Join-Path $root 'evidence')){throw 'Fresh partial controller cache required'}
   $null=New-Item -ItemType Directory -Path (Join-Path $root 'evidence\msix-lifecycle')
   Write-New (Join-Path $root 'evidence\msix-lifecycle\document.txt') $utf8.GetBytes('deliberately incomplete cached copy')
  }
  @{mode=$mode;nonce=$nonce;workerUuid=$uuid;userSid=$account.userSid;rawFiles=@(Get-ChildItem -LiteralPath $source -File -Recurse).Count;applicationExecuted=$false;controlExitCode=42}
 }|ConvertTo-Json -Depth 8 -Compress
}finally{if($session){Remove-PSSession $session};$credential=$null}
