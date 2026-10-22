$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or
   [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or (Get-Process -Id $PID).SessionId -ne 0){throw 'Pinned SYSTEM worker required'}
if(Get-LocalUser AiwStandardUser -ErrorAction SilentlyContinue){throw 'Stage before creating account'}
$staging='C:\AIW-Worker-Setup\msix-vm106-staging'
$operator='S-1-5-21-3849540285-1795134874-2442050430-1006'
foreach($path in @('C:\AIW-Msix-Lifecycle-Input','C:\AIW-Msix-Lifecycle-Output','C:\AIW-VM106-Baseline.json')){if(Test-Path -LiteralPath $path){throw 'Fresh paths required'}}
$expected=@{'application.msix'='2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437';'assembly.json'='d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38';'signing.json'='670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80';'msix_standard_user_lifecycle.exe'='d4bc21662221bd681e0ec89e691a89ff9e4f1902358fdf04975cf438aed147ee';'baseline.json'='1e6f9990e50a90601395dc7f0e0b216481388c98a43a748962bbc92e296eb41a'}
$holds=@()
try {
 foreach($name in $expected.Keys){
  $source=Join-Path $staging $name
  if((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse input'}
  $holds += [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  if((Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -cne $expected[$name]){throw 'Source input hash differs'}
 }
 $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $staging 'application.msix')
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -cne 'CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US' -or !$signature.TimeStamperCertificate){throw 'Signed publisher/timestamp differs'}
 foreach($directory in @('C:\AIW-Msix-Lifecycle-Input','C:\AIW-Msix-Lifecycle-Output')){
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-18'))
  foreach($sid in @('S-1-5-18',$operator)){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  [IO.Directory]::CreateDirectory($directory,$acl)|Out-Null
 }
 foreach($name in $expected.Keys){
  $destination=if($name -eq 'baseline.json'){'C:\AIW-VM106-Baseline.json'}else{Join-Path 'C:\AIW-Msix-Lifecycle-Input' $name}
  [IO.File]::Copy((Join-Path $staging $name),$destination,$false)
  if((Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant() -cne $expected[$name]){throw 'Staged input differs'}
 }
 [ordered]@{staged=$true;files=$expected;signatureValid=$true;timestampPresent=$true;applicationExecuted=$false}|ConvertTo-Json -Depth 4 -Compress
} finally {foreach($held in $holds){$held.Dispose()}}
