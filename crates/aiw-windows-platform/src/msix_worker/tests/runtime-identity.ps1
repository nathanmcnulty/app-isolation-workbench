#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
trap{[Console]::Error.WriteLine($_.ToString()+[Environment]::NewLine+$_.ScriptStackTrace);exit 1}
$root=$PSScriptRoot
function Read-AiwTestAst([string]$Path) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 return $ast
}
function Copy-AiwTestValue($Value){ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 20 -Compress) -AsHashtable}
function Reverse-AiwTestIdentity($Value) {
 $copy=Copy-AiwTestValue $Value;$result=[ordered]@{}
 $keys=@($copy.Keys);[array]::Reverse($keys)
 foreach($key in $keys){
  if($key -ceq 'engine'){$nested=[ordered]@{};$engineKeys=@($copy.engine.Keys);[array]::Reverse($engineKeys);foreach($name in $engineKeys){$nested[$name]=$copy.engine[$name]};$result[$key]=$nested}
  else{$result[$key]=$copy[$key]}
 }
 return $result
}
$totalAccepted=0;$totalRejected=0
foreach($script in @('system.ps1','lifecycle.ps1')) {
 $ast=Read-AiwTestAst (Join-Path $root $script)
 # Execute definitions and guard calls from the actual generated consumers.
 foreach($name in @('New-AiwRuntimeCommonIdentity','New-AiwDirectRuntimeIdentity','Assert-AiwIdentityObject','ConvertTo-AiwClosedWorkerRuntime','Assert-AiwWorkerRuntimeIdentity')) {
  $definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
  if($definitions.Count -ne 1){throw "One compiled identity definition required: $script/$name"}
  . ([scriptblock]::Create($definitions[0].Extent.Text))
 }
 $guards=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Assert-AiwWorkerRuntimeIdentity'},$true))
 if($guards.Count -ne 1){throw "One actual embedded guard required: $script"}
 $guard=[scriptblock]::Create($guards[0].Extent.Text)
 $reads=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$request'},$true))
 if($reads.Count -ne 1){throw 'One actual request read required'}
 # Preserve the generated script's file identity so its actual PSScriptRoot
 # request read resolves normally; do not rewrite the production expression.
 $tokens=$null;$errors=$null
 $readAst=[Management.Automation.Language.Parser]::ParseInput($reads[0].Extent.Text,(Join-Path $root $script),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 . $readAst.GetScriptBlock()
 $originalRequest=$request
 $expected=$request.powerShellRuntime.worker
 # These are inert observations supplied to the production constructors. The
 # actual machine proof still obtains them from its process/loaded assembly.
 $common=New-AiwRuntimeCommonIdentity $expected.edition $expected.version $expected.architecture $expected.psHome (Copy-AiwTestValue $expected.engine) @($expected.capabilities) ([int]0)
 $observed=New-AiwDirectRuntimeIdentity $common $expected.executable $expected.executableSha256
 if((ConvertTo-Json -InputObject $observed -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $expected -Depth 8 -Compress)){throw 'Regression lost the original production JSON-order mismatch'}
 function Invoke-AiwTestGuard($Observation,$Request) {
  $AiwPowerShellRuntime=$Observation;$request=$Request
  & $guard
 }
 function Assert-AiwTestRejection($Observation,$Request,[string]$Label) {
  $rejected=$false
  try{Invoke-AiwTestGuard $Observation $Request}catch{$rejected=$true}
  if(!$rejected){throw "Embedded guard accepted $script/$Label"}
  $script:totalRejected++
 }
 # Unmodified serde_json::to_vec(&MsixWorkerRequest) request and actual direct
 # construction must pass without a JSON Value-map serialization roundtrip.
 Invoke-AiwTestGuard $observed $originalRequest;$totalAccepted++
 $reordered=Copy-AiwTestValue $originalRequest
 $reordered.powerShellRuntime.worker=Reverse-AiwTestIdentity $expected
 foreach($observation in @($observed,(Reverse-AiwTestIdentity $observed))) {
  foreach($inputRequest in @($originalRequest,$reordered)){Invoke-AiwTestGuard $observation $inputRequest;$totalAccepted++}
 }
 $drift=[ordered]@{edition='Desktop';version='7.6.8';prerelease='preview.1';architecture='X86';executable='C:\Other\pwsh.exe';psHome='C:\Other';executableSha256=('f'*64);capabilities=@('proxy');compatibilitySessionCount=1}
 $engineDrift=[ordered]@{assemblyPath='C:\Other\System.Management.Automation.dll';assemblySha256=('e'*64);assemblyVersion='7.6.1.500';moduleVersionId='11111111-1111-1111-1111-111111111111'}
 foreach($side in @('request','observation')) {
  foreach($field in @($drift.Keys)+@('engine')) {
   foreach($mode in @('missing','null','wrongType','drift')) {
    $badRequest=Copy-AiwTestValue $originalRequest;$badObservation=Copy-AiwTestValue $observed
    $target=if($side -ceq 'request'){$badRequest.powerShellRuntime.worker}else{$badObservation}
    switch($mode){
     missing{[void]$target.Remove($field)}
     null{$target[$field]=$null}
     wrongType{$target[$field]=$false}
     drift{if($field -ceq 'engine'){$target.engine.assemblySha256='e'*64}else{$target[$field]=$drift[$field]}}
    }
    Assert-AiwTestRejection $badObservation $badRequest "$side/$field/$mode"
   }
  }
  foreach($field in $engineDrift.Keys) {
   foreach($mode in @('missing','null','wrongType','drift')) {
    $badRequest=Copy-AiwTestValue $originalRequest;$badObservation=Copy-AiwTestValue $observed
    $target=if($side -ceq 'request'){$badRequest.powerShellRuntime.worker.engine}else{$badObservation.engine}
    switch($mode){missing{[void]$target.Remove($field)} null{$target[$field]=$null} wrongType{$target[$field]=42} drift{$target[$field]=$engineDrift[$field]}}
    Assert-AiwTestRejection $badObservation $badRequest "$side/engine/$field/$mode"
   }
  }
  foreach($scope in @('worker','engine')) {
   $badRequest=Copy-AiwTestValue $originalRequest;$badObservation=Copy-AiwTestValue $observed
   $target=if($side -ceq 'request'){$badRequest.powerShellRuntime.worker}else{$badObservation}
   if($scope -ceq 'engine'){$target=$target.engine}
   $target['unexpected']='extra'
   Assert-AiwTestRejection $badObservation $badRequest "$side/$scope/extra"
  }
  $badRequest=Copy-AiwTestValue $originalRequest;$badObservation=Copy-AiwTestValue $observed
  $target=if($side -ceq 'request'){$badRequest.powerShellRuntime.worker}else{$badObservation}
  $value=$target.edition;[void]$target.Remove('edition');$target['Edition']=$value
  Assert-AiwTestRejection $badObservation $badRequest "$side/cased-key"
 }
 foreach($count in @('0',$false,[double]0,[decimal]0,-1,4294967296L)) {
  $bad=Copy-AiwTestValue $originalRequest;$bad.powerShellRuntime.worker.compatibilitySessionCount=$count
  Assert-AiwTestRejection $observed $bad 'nonzero-or-noninteger-count'
 }
 foreach($mode in @('reordered','duplicate','scalar','object','number','nested')) {
  $bad=Copy-AiwTestValue $originalRequest;$caps=@($expected.capabilities)
  switch($mode){
   reordered{$swap=$caps[0];$caps[0]=$caps[1];$caps[1]=$swap}
   duplicate{$caps[1]=$caps[0]}
   scalar{$caps=$expected.capabilities -join '|'}
   object{$caps=@{name='Add-Type'}}
   number{$caps[0]=42}
   nested{$caps[0]=@('Add-Type')}
  }
  $bad.powerShellRuntime.worker.capabilities=$caps
  Assert-AiwTestRejection $observed $bad "capabilities/$mode"
 }
 foreach($path in @('pwsh.exe','C:\Users\labadmin\pwsh.exe','C:\Program Files\WindowsApps\pwsh.exe','C:\Windows\System32\wsmprovhost.exe')) {
  $bad=Copy-AiwTestValue $originalRequest;$bad.powerShellRuntime.worker.executable=$path
  Assert-AiwTestRejection $observed $bad 'alternate-direct-image'
 }
 foreach($field in @('host','worker','endpoint','wsman')) {
  $bad=Copy-AiwTestValue $originalRequest;[void]$bad.powerShellRuntime.Remove($field)
  Assert-AiwTestRejection $observed $bad "binding/missing/$field"
 }
 foreach($binding in @($null,'invalid',42,@(),@{})) {
  $bad=Copy-AiwTestValue $originalRequest;$bad.powerShellRuntime=$binding
  Assert-AiwTestRejection $observed $bad 'invalid-binding'
 }
 $bad=Copy-AiwTestValue $originalRequest;[void]$bad.Remove('powerShellRuntime')
 Assert-AiwTestRejection $observed $bad 'historical-no-binding'
 $bad=Copy-AiwTestValue $originalRequest;$bad.powerShellRuntime.worker=$bad.powerShellRuntime.wsman
 Assert-AiwTestRejection $observed $bad 'endpoint-as-approved-worker'
 Assert-AiwTestRejection $originalRequest.powerShellRuntime.wsman $originalRequest 'endpoint-as-observed-worker'
}
[ordered]@{passed=$true;consumers=2;accepted=$totalAccepted;rejected=$totalRejected;requestBytesPreserved=$true;vmContacted=$false;applicationExecuted=$false}|ConvertTo-Json -Compress
