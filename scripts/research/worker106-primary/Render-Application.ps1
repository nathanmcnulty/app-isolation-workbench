param([ValidatePattern('^C:\\passkeys\\worker106-tools\\primary-vm106-r[0-9]+$')][string]$ReceiptRoot='C:\passkeys\worker106-tools\primary-vm106-r1')
# Controller-only rendering of the closed archived Scheduler templates.
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ieq '7e686bee-8c05-43c7-9603-a9562ece224c'){throw 'Render on controller only'}
$root=$ReceiptRoot
$account=Get-Content -LiteralPath (Join-Path $root 'created.json') -Raw|ConvertFrom-Json
$prepared=Get-Content -LiteralPath (Join-Path $root 'preparation.json') -Raw|ConvertFrom-Json
$nonce=[string]$account.runNonce;$sid=[string]$account.userSid;$hash=[string]$prepared.preparationSha256
if($nonce -cnotmatch '\A[0-9a-f]{64}\z' -or $sid -cnotmatch '\AS-1-5-21-3849540285-1795134874-2442050430-([0-9]+)\z' -or
   [long]$Matches[1] -lt 1000 -or $sid -ceq 'S-1-5-21-3849540285-1795134874-2442050430-1006' -or $hash -cnotmatch '\A[0-9a-f]{64}\z' -or
   !$account.accountCreated -or $account.accountName -cne 'AiwStandardUser' -or $account.vmId -cne '7e686bee-8c05-43c7-9603-a9562ece224c' -or
   $prepared.prepared.runNonce -cne $nonce -or $prepared.prepared.userSid -cne $sid -or $prepared.prepared.vmId -cne $account.vmId -or
   $prepared.prepared.sourceImageSha256 -cne '6d312e1ad135c9bfe8be36cc810079e5607f021f514af4320c1458930fa7437d' -or
   $prepared.prepared.sessionId -le 0 -or [DateTime]::UtcNow.ToFileTimeUtc() -gt $prepared.prepared.notAfterFileTime){throw 'Actual fresh account/preparation binding differs'}
$worker=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'application-worker.template.ps1')).Replace('@@ROOT@@',('C:\AIW-Task-Primary-'+$nonce)).Replace('@@NONCE@@',$nonce).Replace('@@USER_SID@@',$sid).Replace('@@PREP_SHA@@',$hash)
$encoded=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($worker))
$controller=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'application-controller.template.ps1')).Replace('@@NONCE@@',$nonce).Replace('@@USER_SID@@',$sid).Replace('@@WORKER_B64@@',$encoded)
if($worker -match '@@[A-Z_]+@@' -or $controller -match '@@[A-Z_]+@@'){throw 'Unbound template field'}
foreach($entry in @(@{name='worker.ps1';text=$worker},@{name='controller.ps1';text=$controller})){
 $path=Join-Path $root $entry.name
 $file=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes($entry.text)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
[ordered]@{nonce=$nonce;userSid=$sid;preparationSha256=$hash;workerSha256=(Get-FileHash (Join-Path $root worker.ps1)).Hash.ToLowerInvariant();controllerSha256=(Get-FileHash (Join-Path $root controller.ps1)).Hash.ToLowerInvariant()}|ConvertTo-Json -Compress
