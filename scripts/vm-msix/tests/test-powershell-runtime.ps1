#Requires -Version 7.6
#Requires -PSEdition Core
# Bounded, local-only source/ACL regressions. No VM, WinRM or application is used.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\..\powershell-runtime.ps1')
$runtime=Assert-AiwPowerShellRuntime -AllowCurrentProcessForInertTests
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
function Read-Ast([string]$Path) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 $ast
}
$transport=Read-Ast (Join-Path $repo 'scripts\vm-msix\transport.ps1')
$observer=Read-Ast (Join-Path $repo 'scripts\vm-msix\observe-runtime.ps1')
function Get-OneAst($Ast,[string]$Name,[type]$Type) {
 $nodes=@($Ast.FindAll({param($node) $node -is $Type -and (($node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name) -or ($node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq ('$'+$Name)))},$true))
 if($nodes.Count -ne 1){throw "Expected one $Name; found $($nodes.Count)"};$nodes[0]
}
$proof=Get-OneAst $transport 'runtimeProof' ([Management.Automation.Language.AssignmentStatementAst])
$observationProof=Get-OneAst $observer 'runtimeProof' ([Management.Automation.Language.AssignmentStatementAst])
if($proof.Extent.Text -cne $observationProof.Extent.Text){throw 'Runtime observation and execution proof must be identical'}
$nativeGuard=Read-Ast (Join-Path $repo 'crates\aiw-probe\src\powershell_runtime.ps1')
if($proof.Extent.Text -cne (Get-OneAst $nativeGuard 'runtimeProof' ([Management.Automation.Language.AssignmentStatementAst])).Extent.Text){throw 'Direct worker, observer and transport must use the same proof'}
$source=$transport.Extent.Text
foreach($forbidden in @('ConfigurationName Microsoft.PowerShell','WindowsPowerShell\v1.0\powershell.exe','-UseWindowsPowerShell','SkipCACheck','SkipCNCheck','SkipRevocationCheck')){if($source.Contains($forbidden)){throw "Forbidden execution route: $forbidden"}}
if($source.IndexOf('Legacy prepared workspace') -gt $source.IndexOf('$stored=Import-Clixml')){throw 'Legacy runtime binding must be rejected before credential import'}
if($source.IndexOf('Assert-AiwRuntimeBinding $workerRuntime') -gt $source.IndexOf("if(`$Operation -eq 'Ready')")){throw 'Remote proof must precede any operation'}
$binding=Get-OneAst $transport 'Assert-AiwRuntimeBinding' ([Management.Automation.Language.FunctionDefinitionAst])
. ([scriptblock]::Create($binding.Extent.Text))
$engine=[pscustomobject]@{assemblyPath='C:\Program Files\PowerShell\7\System.Management.Automation.dll';assemblySha256=('b'*64);assemblyVersion='7.6.0.500';moduleVersionId='8ca1bab3-ea9c-44c4-844d-952330c02c88'}
$capabilities=@('Add-Type','Get-CimInstance','Get-AppxPackage','Get-AppxPackageManifest','Add-AppxPackage','Remove-AppxPackage','Get-AppxProvisionedPackage','Get-LocalUser','New-LocalUser','Disable-LocalUser','Add-LocalGroupMember','Get-LocalGroupMember','Get-AuthenticodeSignature','Get-ScheduledTask','New-PSSession')
$identity=[pscustomobject]@{edition='Core';version='7.6.5';prerelease='';architecture='X64';executable='C:\Program Files\PowerShell\7\pwsh.exe';psHome='C:\Program Files\PowerShell\7';executableSha256=('a'*64);capabilities=$capabilities;compatibilitySessionCount=0;engine=$engine}
Assert-AiwRuntimeBinding $identity $identity
$rejected=0
foreach($field in @('edition','version','prerelease','architecture','executable','psHome','executableSha256','compatibilitySessionCount','capabilities')) {
 $changed=$identity|ConvertTo-Json|ConvertFrom-Json
 if($field -ceq 'capabilities'){$changed.capabilities=@('New-PSSession')}else{$changed.$field='different'}
 try{Assert-AiwRuntimeBinding $changed $identity;throw 'Expected rejected runtime mismatch'}catch{if($_.Exception.Message -like 'Expected rejected*'){throw};$rejected++}
}
try{Assert-AiwRuntimeBinding $identity $null;throw 'Expected rejected missing runtime'}catch{if($_.Exception.Message -like 'Expected rejected*'){throw};$rejected++}
function Assert-Rejected([scriptblock]$Action) {
 try{& $Action;throw 'Expected rejected unsafe identity'}catch{if($_.Exception.Message -like 'Expected rejected*'){throw}}
}
foreach($name in @('Assert-AiwRuntimeObservation','Assert-AiwWsmanConfiguration','Open-AiwProofFile','Get-AiwProofHash')){
 . ([scriptblock]::Create((Get-OneAst $nativeGuard $name ([Management.Automation.Language.FunctionDefinitionAst])).Extent.Text))
}
Assert-AiwRuntimeObservation $identity Direct
$wsman=[pscustomobject]@{edition='Core';version='7.6.5';prerelease='';architecture='X64';psHome='C:\Program Files\PowerShell\7';engine=$engine;capabilities=$capabilities;compatibilitySessionCount=0;configurationName='PowerShell.7.6';hostKind='WSMan';hostExecutable='C:\Windows\System32\wsmprovhost.exe';hostExecutableSha256=('c'*64);pluginPath='C:\Windows\System32\PowerShell\7.6.5\pwrshplugin.dll';pluginSha256=('d'*64);configurationSha256=('e'*64);startupConfigSha256=('f'*64);resourceUri='http://schemas.microsoft.com/powershell/PowerShell.7.6';configurationPsHome='C:\Program Files\PowerShell\7';configurationCoreclrDir='C:\Program Files\PowerShell\7'}
Assert-AiwRuntimeObservation $wsman WSMan
Assert-Rejected {Assert-AiwRuntimeObservation $identity WSMan}
Assert-Rejected {Assert-AiwRuntimeObservation $wsman Direct}
$hostRejections=2
$badObservations=@(
 @{edition='Desktop'},@{version='5.1.26100.1'},@{version='7.5.4'},@{prerelease='preview.1'},@{architecture='X86'},@{psHome='C:\Other'},
 @{compatibilitySessionCount=1},@{capabilities=@('proxy')},@{hostKind='Direct'},@{hostExecutable='C:\Program Files\PowerShell\7\pwsh.exe'},
 @{configurationName='Microsoft.PowerShell'},@{resourceUri='http://schemas.microsoft.com/powershell/Other'},
 @{pluginPath='C:\Windows\System32\PowerShell\7.6.7\pwrshplugin.dll'},@{configurationPsHome='C:\Other'},@{configurationCoreclrDir='C:\Other'}
)
foreach($change in $badObservations){
 $bad=$wsman|ConvertTo-Json -Depth 8|ConvertFrom-Json
 foreach($pair in $change.GetEnumerator()){$bad.($pair.Key)=$pair.Value}
 Assert-Rejected {Assert-AiwRuntimeObservation $bad WSMan};$hostRejections++
}
foreach($path in @('C:\Users\user\pwsh.exe','C:\Users\user\AppData\Local\Microsoft\WindowsApps\pwsh.exe','pwsh.exe','C:\Windows\System32\wsmprovhost.exe')){
 $bad=$identity|ConvertTo-Json -Depth 8|ConvertFrom-Json;$bad.executable=$path
 Assert-Rejected {Assert-AiwRuntimeObservation $bad Direct};$hostRejections++
}
foreach($field in @('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')){
 $bad=$wsman|ConvertTo-Json -Depth 8|ConvertFrom-Json;$bad.engine.$field='unexpected'
 Assert-Rejected {Assert-AiwRuntimeObservation $bad WSMan};$hostRejections++
}
$wsmanBinding=Get-OneAst $transport 'Assert-AiwWsmanBinding' ([Management.Automation.Language.FunctionDefinitionAst])
. ([scriptblock]::Create($wsmanBinding.Extent.Text))
Assert-AiwWsmanBinding $wsman $wsman
$bindingRejections=0
foreach($field in @('configurationName','hostKind','hostExecutable','hostExecutableSha256','version','pluginPath','pluginSha256','configurationSha256','startupConfigSha256','resourceUri','configurationPsHome','configurationCoreclrDir','capabilities')){
 $bad=$wsman|ConvertTo-Json -Depth 8|ConvertFrom-Json
 if($field -ceq 'capabilities'){$bad.capabilities=@('proxy')}else{$bad.$field='changed'}
 Assert-Rejected {Assert-AiwWsmanBinding $bad $wsman};$bindingRejections++
}
foreach($field in @('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')){
 $bad=$identity|ConvertTo-Json -Depth 8|ConvertFrom-Json;$bad.engine.$field='changed'
 Assert-Rejected {Assert-AiwRuntimeBinding $bad $identity};$bindingRejections++
}
Assert-Rejected {Assert-AiwWsmanBinding $wsman $null};$bindingRejections++
# Execute the actual registration parser against an upstream-shaped inert value.
$config='<PlugInConfiguration xmlns="http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration" Name="PowerShell.7.6" Filename="%windir%\system32\PowerShell\7.6.5\pwrshplugin.dll" Enabled="True" SDKVersion="2" XmlRenderingType="text" Architecture="64" UseSharedProcess="false"><InitializationParameters><Param Name="PSVersion" Value="7.6"/></InitializationParameters><Resources><Resource SupportsOptions="true" ResourceUri="http://schemas.microsoft.com/powershell/PowerShell.7.6" ExactMatch="true"><Security Uri="http://schemas.microsoft.com/powershell/PowerShell.7.6" ExactMatch="true" Sddl="O:BAG:BAD:P(A;;GA;;;SY)"/><Capability Type="Shell"/></Resource></Resources></PlugInConfiguration>'
$startup='PSHOMEDIR=C:\Program Files\PowerShell\7'+[Environment]::NewLine+'CORECLRDIR=C:\Program Files\PowerShell\7'+[Environment]::NewLine
$parsed=Assert-AiwWsmanConfiguration $config $startup '7.6.5'
if($parsed.pluginPath -ine $wsman.pluginPath -or $parsed.resourceUri -cne $wsman.resourceUri){throw 'Valid endpoint registration was not accepted'}
$badConfigs=@(
 $config.Replace('Name="PowerShell.7.6"','Name="Other"'),$config.Replace('Architecture="64"','Architecture="32"'),
 $config.Replace('Enabled="True"','Enabled="False"'),$config.Replace('UseSharedProcess="false"','UseSharedProcess="true"'),
 $config.Replace('SDKVersion="2"','SDKVersion="2" RunAsVirtualAccount="true"'),$config.Replace('SDKVersion="2"','SDKVersion="2" RunAsUser="other"'),
 $config.Replace('Value="7.6"','Value="5.1"'),$config.Replace('Name="PSVersion"','Name="ConfigFilePath"'),
 $config.Replace('SupportsOptions="true"','SupportsOptions="false"'),$config.Replace('ExactMatch="true"','ExactMatch="false"'),
 $config.Replace('<Param Name=','<Param xmlns="urn:unexpected" Name='),$config.Replace('7.6.5\pwrshplugin.dll','7.6.7\pwrshplugin.dll'),
 $config.Replace('<Resources><Resource SupportsOptions="true"', '<Resources SupportsOptions="true"><Resource'),
 ('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///does-not-exist">]>'+$config),('x'*65537)
)
foreach($bad in $badConfigs){Assert-Rejected {Assert-AiwWsmanConfiguration $bad $startup '7.6.5'} }
foreach($bad in @($startup.Replace('CORECLRDIR=C:\Program Files\PowerShell\7','CORECLRDIR=C:\Other'),($startup+'PSHOMEDIR=C:\Program Files\PowerShell\7'),('x'*8193))){Assert-Rejected {Assert-AiwWsmanConfiguration $config $bad '7.6.5'}}
# Exercise the actual native-command origin check with an implicit-remoting
# proxy that still advertises the expected command name.
$nativeCheck=@($nativeGuard.FindAll({param($node)$node -is [Management.Automation.Language.ForEachStatementAst] -and $node.Variable.Extent.Text -ceq '$name' -and $node.Condition.Extent.Text -ceq '$caps'},$true))
if($nativeCheck.Count -ne 1){throw 'Exact native command origin check required'}
try{
 function Get-Command { [CmdletBinding()]param($Name) [pscustomobject]@{CommandType='Function';Module=[pscustomobject]@{Path='C:\Temp\implicit-remoting-proxy.psm1'};ModuleName='ImplicitRemoting'} }
 $caps=@('Get-AppxPackage');$fixedHome='C:\Program Files\PowerShell\7'
 Assert-Rejected {& ([scriptblock]::Create($nativeCheck[0].Extent.Text))}
}finally{Remove-Item -LiteralPath Function:Get-Command}
# Exercise the exact consumer loop for the native PSHOME CIM binary layout.
$cimImage='C:\Program Files\PowerShell\7\Microsoft.Management.Infrastructure.CimCmdlets.dll'
$cimCommand=[pscustomobject]@{CommandType='Cmdlet';ModuleName='CimCmdlets';Module=[pscustomobject]@{Path=$cimImage};ImplementingType=[pscustomobject]@{Assembly=[pscustomobject]@{Location=$cimImage}}}
$cimRejections=0
try{
 function Get-Command { [CmdletBinding()]param($Name) $cimCommand }
 $caps=@('Get-CimInstance');$fixedHome='C:\Program Files\PowerShell\7'
 & ([scriptblock]::Create($nativeCheck[0].Extent.Text))
 $goodCim=$cimCommand|ConvertTo-Json -Depth 8
 foreach($change in @('Function','Alias','WrongModule','ModuleInOtherHome','ModuleUnderModules','AssemblyInOtherHome','MissingModule')){
  $cimCommand=$goodCim|ConvertFrom-Json
  switch($change){
   'Function' {$cimCommand.CommandType='Function'}
   'Alias' {$cimCommand.CommandType='Alias'}
   'WrongModule' {$cimCommand.ModuleName='ImplicitRemoting'}
   'ModuleInOtherHome' {$cimCommand.Module.Path='C:\Other\Microsoft.Management.Infrastructure.CimCmdlets.dll'}
   'ModuleUnderModules' {$cimCommand.Module.Path='C:\Program Files\PowerShell\7\Modules\Proxy\Proxy.psm1'}
   'AssemblyInOtherHome' {$cimCommand.ImplementingType.Assembly.Location='C:\Other\Microsoft.Management.Infrastructure.CimCmdlets.dll'}
   'MissingModule' {$cimCommand.Module=$null}
  }
  Assert-Rejected {& ([scriptblock]::Create($nativeCheck[0].Extent.Text))};$cimRejections++
 }
}finally{Remove-Item -LiteralPath Function:Get-Command}
# Execute the actual loaded-engine capture statements on the existing test Core.
$assemblyAst=Get-OneAst $nativeGuard 'assembly' ([Management.Automation.Language.AssignmentStatementAst])
$engineAst=Get-OneAst $nativeGuard 'engine' ([Management.Automation.Language.AssignmentStatementAst])
$capture=$nativeGuard.Extent.Text.Substring($assemblyAst.Extent.StartOffset,$engineAst.Extent.EndOffset-$assemblyAst.Extent.StartOffset)
$held=[Collections.Generic.List[IO.FileStream]]::new();$fixedHome=$PSHOME
try {
 . ([scriptblock]::Create($capture))
 if($engine.assemblyPath -ine ([PSObject].Assembly.Location) -or $engine.moduleVersionId -cne ([PSObject].Assembly.ManifestModule.ModuleVersionId.ToString())){throw 'Actual loaded engine capture differs'}
 $fixedHome='C:\Unexpected';Assert-Rejected {. ([scriptblock]::Create($capture))}
}finally{foreach($stream in $held){$stream.Dispose()}}
# A linked parent must be rejected by the real file opener, without releasing a
# normal held image's read/write/delete boundary.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('aiw-engine-proof-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixture
$physical=Join-Path $fixture 'physical';$link=Join-Path $fixture 'linked'
$null=New-Item -ItemType Directory -Path $physical
[IO.File]::WriteAllText((Join-Path $physical 'image.dll'),'inert engine fixture')
$held=[Collections.Generic.List[IO.FileStream]]::new()
try{
 $stream=Open-AiwProofFile (Join-Path $physical 'image.dll')
 Assert-Rejected {[IO.File]::WriteAllText((Join-Path $physical 'image.dll'),'changed')}
 $null=New-Item -ItemType Junction -Path $link -Target $physical
 Assert-Rejected {Open-AiwProofFile (Join-Path $link 'image.dll')}
}finally{
 foreach($stream in $held){$stream.Dispose()}
 $full=[IO.Path]::GetFullPath($fixture);$tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
 if(!$full.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $full) -notmatch '^aiw-engine-proof-[0-9a-f]{32}$'){throw 'Unsafe engine fixture cleanup target'}
 if(Test-Path -LiteralPath $link){Remove-Item -LiteralPath $link -Force}
 Remove-Item -LiteralPath $full -Recurse -Force
}
$creation=Get-OneAst $transport 'New-AiwProtectedDirectory' ([Management.Automation.Language.FunctionDefinitionAst])
. ([scriptblock]::Create($creation.Extent.Text))
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('aiw-pwsh76-acl-'+[guid]::NewGuid().ToString('N'))
$created=$false
try {
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($sid)
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 New-AiwProtectedDirectory $temporary $acl;$created=$true
 $before=(Get-Acl -LiteralPath $temporary).Sddl
 try{New-AiwProtectedDirectory $temporary $acl;throw 'Expected rejected existing directory'}catch{if($_.Exception.Message -notlike '*Fresh protected directory required*'){throw}}
 if((Get-Acl -LiteralPath $temporary).Sddl -cne $before){throw 'Existing protected directory ACL changed'}
}finally{if($created){Remove-Item -LiteralPath $temporary -Force}}
$retiredManifest=Get-Content -LiteralPath (Join-Path $repo 'scripts\research\RETIRED-EXECUTION.md') -Raw
$paths=[regex]::Matches($retiredManifest,'(?m)^- `([^`]+)`$')
foreach($match in $paths){
 $path=Join-Path $repo $match.Groups[1].Value
 $text=[IO.File]::ReadAllText($path)
 if($path.EndsWith('.ps1') -or $path.EndsWith('.in')){
  $ast=Read-Ast $path
  if(@($ast.FindAll({param($node) $node -is [Management.Automation.Language.ThrowStatementAst]},$true)).Count -ne 1 -or @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)).Count -ne 0){throw "Retired PowerShell route became active: $path"}
 }elseif($path.EndsWith('.py')){if($text -notmatch 'raise SystemExit' -or $text -match '(?m)^import |(?m)^from '){throw "Retired Python route became active: $path"}}
}
[pscustomobject]@{passed=$true;runtimeVersion=$runtime.version;nativeCimAccepted=$true;nativeCimRejections=$cimRejections;runtimeBindingRejections=$rejected;wsmanHostRejections=$hostRejections;endpointOrWorkerDriftRejections=$bindingRejections;configurationRejections=($badConfigs.Count+3);implicitProxyRejected=$true;loadedEngineCapture=$true;linkedImageRejected=$true;aclAtCreation=$true;existingAclPreserved=$true;retiredEntryPoints=$paths.Count;vmContacted=$false;applicationExecuted=$false}|ConvertTo-Json -Compress
