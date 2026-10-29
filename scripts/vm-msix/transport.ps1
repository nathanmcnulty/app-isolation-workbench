#Requires -Version 7.6
#Requires -PSEdition Core
# Fixed production transport. The approved native worker owns application execution.
param(
 [Parameter(Mandatory)][ValidateSet('Clean','Stage','Enroll','Restart','Ready','Control','Run','Status','Collect')][string]$Operation,
 [Parameter(Mandatory)][ValidatePattern('\A[a-zA-Z0-9-]{1,96}\z')][string]$RunId,
 [Parameter(Mandatory)][string]$Workspace
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$ProgressPreference='SilentlyContinue'
# Runtime proof is fixed source, reused locally and on the explicit endpoint.
$runtimeProof = {
 param([ValidateSet('Direct','WSMan')][string]$Kind='Direct',[string]$DirectProofSource)
 $ErrorActionPreference='Stop';$global:PSModuleAutoLoadingPreference='None'
 $fixedHome='C:\Program Files\PowerShell\7'
 $caps=@('Add-Type','Get-CimInstance','Get-AppxPackage','Get-AppxPackageManifest','Add-AppxPackage','Remove-AppxPackage','Get-AppxProvisionedPackage','Get-LocalUser','New-LocalUser','Disable-LocalUser','Add-LocalGroupMember','Get-LocalGroupMember','Get-AuthenticodeSignature','Get-ScheduledTask','New-PSSession')
 function New-AiwRuntimeCommonIdentity($Edition,$Version,$Architecture,$RuntimeHome,$Engine,$Capabilities,$CompatibilityCount) {
  return [ordered]@{edition=$Edition;version=$Version;prerelease='';architecture=$Architecture;psHome=$RuntimeHome;engine=$Engine;capabilities=$Capabilities;compatibilitySessionCount=$CompatibilityCount}
 }
 function New-AiwDirectRuntimeIdentity($Common,$Executable,$ExecutableSha256) {
  $direct=[ordered]@{};foreach($key in $Common.Keys){$direct[$key]=$Common[$key]};$direct.executable=$Executable;$direct.executableSha256=$ExecutableSha256
  return $direct
 }
 function Assert-AiwRuntimeObservation {
  param($Observation,[ValidateSet('Direct','WSMan')][string]$Kind='Direct')
  $expectedHome='C:\Program Files\PowerShell\7'
  if($Observation.edition -cne 'Core' -or $Observation.version -notmatch '^\d+\.\d+\.\d+(\.\d+)?$' -or [version]$Observation.version -lt [version]'7.6' -or $Observation.prerelease -cne '' -or $Observation.architecture -cne 'X64' -or $Observation.psHome -ine $expectedHome -or $Observation.compatibilitySessionCount -ne 0){throw 'Stable native x64 Core runtime observation required'}
  $required=@('Add-Type','Get-CimInstance','Get-AppxPackage','Get-AppxPackageManifest','Add-AppxPackage','Remove-AppxPackage','Get-AppxProvisionedPackage','Get-LocalUser','New-LocalUser','Disable-LocalUser','Add-LocalGroupMember','Get-LocalGroupMember','Get-AuthenticodeSignature','Get-ScheduledTask','New-PSSession')
  if(@($Observation.capabilities).Count -ne $required.Count){throw 'Incomplete native capabilities'}
  foreach($capability in $required){if(@($Observation.capabilities) -cnotcontains $capability){throw 'Incomplete native capabilities'}}
  if($Observation.engine.assemblyPath -ine ($expectedHome+'\System.Management.Automation.dll') -or $Observation.engine.assemblySha256 -cnotmatch '^[0-9a-f]{64}$' -or $Observation.engine.assemblyVersion -notmatch '^\d+\.\d+\.\d+\.\d+$' -or $Observation.engine.moduleVersionId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$'){throw 'Exact loaded engine identity required'}
  if(([version]$Observation.engine.assemblyVersion).Major -ne ([version]$Observation.version).Major -or ([version]$Observation.engine.assemblyVersion).Minor -ne ([version]$Observation.version).Minor -or [guid]$Observation.engine.moduleVersionId -eq [guid]::Empty){throw 'Engine version or MVID mismatch'}
  if($Kind -ceq 'Direct'){
   if($Observation.executable -ine ($expectedHome+'\pwsh.exe') -or $Observation.executableSha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Exact direct PowerShell executable required'}
  }else{
   if($Observation.configurationName -cne 'PowerShell.7.6' -or $Observation.hostKind -cne 'WSMan' -or $Observation.hostExecutable -ine 'C:\Windows\System32\wsmprovhost.exe' -or $Observation.hostExecutableSha256 -cnotmatch '^[0-9a-f]{64}$' -or $Observation.resourceUri -cne 'http://schemas.microsoft.com/powershell/PowerShell.7.6' -or $Observation.configurationPsHome -ine $expectedHome -or $Observation.configurationCoreclrDir -ine $expectedHome){throw 'Exact WSMan host and endpoint required'}
   foreach($field in @('pluginSha256','configurationSha256','startupConfigSha256')){if($Observation.$field -cnotmatch '^[0-9a-f]{64}$'){throw 'Incomplete WSMan configuration identity'}}
   if($Observation.pluginPath -ine ($expectedHome+'\pwrshplugin.dll') -and $Observation.pluginPath -ine ('C:\Windows\System32\PowerShell\'+$Observation.version+'\pwrshplugin.dll')){throw 'Unexpected WSMan plugin path'}
  }
 }
 function Assert-AiwWsmanConfiguration {
  param([string]$ConfigXml,[string]$StartupText,[string]$RuntimeVersion,[switch]$ConfigurationOnly)
  $fixedHome='C:\Program Files\PowerShell\7'
  if([string]::IsNullOrWhiteSpace($ConfigXml) -or [Text.Encoding]::UTF8.GetByteCount($ConfigXml) -gt 65536){throw 'WSMan configuration XML length invalid'}
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
  $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($configXml),$settings)
  try{$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader)}finally{$reader.Dispose()}
  $configuration=$xml.DocumentElement
  if($configuration.LocalName -cne 'PlugInConfiguration' -or $configuration.NamespaceURI -cne 'http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration' -or $configuration.GetAttribute('Name') -cne 'PowerShell.7.6' -or $configuration.GetAttribute('Enabled') -ine 'true' -or ($configuration.HasAttribute('Architecture') -and $configuration.GetAttribute('Architecture') -cne '64')){throw 'Unexpected WSMan plugin registration'}
  if($configuration.GetAttribute('SDKVersion') -cne '2' -or $configuration.GetAttribute('XmlRenderingType') -ine 'text' -or ($configuration.HasAttribute('UseSharedProcess') -and $configuration.GetAttribute('UseSharedProcess') -ine 'false')){throw 'Unexpected WSMan plugin execution configuration'}
  foreach($node in @($configuration.SelectNodes('.//*'))){if($node.NamespaceURI -cne $configuration.NamespaceURI){throw 'Unexpected WSMan configuration namespace'}}
  $resourceContainers=@($configuration.SelectNodes("*[local-name()='Resources']"))
  if($resourceContainers.Count -ne 1){throw 'Unexpected WSMan resource options'}
  $initialization=@($configuration.SelectNodes("*[local-name()='InitializationParameters']/*"))
  if($initialization.Count -ne 1 -or $initialization[0].LocalName -cne 'Param' -or $initialization[0].GetAttribute('Name') -cne 'PSVersion' -or $initialization[0].GetAttribute('Value') -cne '7.6'){throw 'Unexpected WSMan initialization authority'}
  $resources=@($configuration.SelectNodes("*[local-name()='Resources']/*[local-name()='Resource']"))
  $uri='http://schemas.microsoft.com/powershell/PowerShell.7.6'
  if($resources.Count -ne 1 -or $resources[0].GetAttribute('SupportsOptions') -ine 'true' -or $resources[0].GetAttribute('ResourceUri') -cne $uri -or $resources[0].GetAttribute('ExactMatch') -ine 'true'){throw 'Unexpected WSMan resource URI'}
  $capabilities=@($resources[0].SelectNodes("*[local-name()='Capability']"));$security=@($resources[0].SelectNodes("*[local-name()='Security']"))
  if($capabilities.Count -ne 1 -or $capabilities[0].GetAttribute('Type') -cne 'Shell' -or $security.Count -ne 1 -or $security[0].GetAttribute('Uri') -cne $uri -or $security[0].GetAttribute('ExactMatch') -ine 'true'){throw 'Unexpected WSMan resource authority'}
  $pluginPath=[Environment]::ExpandEnvironmentVariables($configuration.GetAttribute('Filename'))
  if($pluginPath -ine ($fixedHome+'\pwrshplugin.dll') -and $pluginPath -ine ('C:\Windows\System32\PowerShell\'+$RuntimeVersion+'\pwrshplugin.dll')){throw 'Unexpected registered plugin path'}
  foreach($name in @('RunAsVirtualAccount','RunAsVirtualAccountGroups','RunAsUser','RunAsPassword')){if($configuration.HasAttribute($name) -and ![string]::IsNullOrEmpty($configuration.GetAttribute($name)) -and !($name -ceq 'RunAsVirtualAccount' -and $configuration.GetAttribute($name) -ieq 'false')){throw 'WSMan identity redirection forbidden'}}
  if(!$ConfigurationOnly){
   if([Text.Encoding]::UTF8.GetByteCount($StartupText) -gt 8192){throw 'WSMan startup configuration length invalid'}
   $lines=@($StartupText -split '\r?\n'|Where-Object {$_ -cne ''})
   if($lines.Count -ne 2 -or @($lines|Where-Object {$_ -ceq ('PSHOMEDIR='+$fixedHome)}).Count -ne 1 -or @($lines|Where-Object {$_ -ceq ('CORECLRDIR='+$fixedHome)}).Count -ne 1){throw 'Unexpected WSMan startup redirection'}
  }
  return [ordered]@{pluginPath=$pluginPath;resourceUri=$uri}
 }
 $held=[Collections.Generic.List[IO.FileStream]]::new()
 function Open-AiwProofFile([string]$Path){
  $full=[IO.Path]::GetFullPath($Path)
  if($full -ine $Path){throw 'Noncanonical runtime path'}
  $node=$full
  while($node){if(([IO.File]::GetAttributes($node) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse runtime path forbidden'};$parent=[IO.Path]::GetDirectoryName($node);if($parent -eq $node){break};$node=$parent}
  $stream=[IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $held.Add($stream);return $stream
 }
 function Get-AiwProofHash([IO.Stream]$Stream){$Stream.Position=0;try{return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Stream)).ToLowerInvariant()}finally{$Stream.Position=0}}
 try{
  if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc') -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSHOME -ine $fixedHome){throw 'Stable machine x64 PowerShell Core >=7.6 required'}
  $exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  if(($Kind -ceq 'Direct' -and $exe -ine ($fixedHome+'\pwsh.exe')) -or ($Kind -ceq 'WSMan' -and $exe -ine 'C:\Windows\System32\wsmprovhost.exe')){throw 'Unexpected runtime process host'}
  $exeStream=Open-AiwProofFile $exe
  $assembly=[System.Management.Automation.PSObject].Assembly
  if($assembly.Location -ine ($fixedHome+'\System.Management.Automation.dll')){throw 'Unexpected loaded PowerShell engine'}
  $engineStream=Open-AiwProofFile $assembly.Location
  $pe=[Reflection.PortableExecutable.PEReader]::new($engineStream,[Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen)
  try{$metadata=[Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe);$module=$metadata.GetModuleDefinition();$diskMvid=$metadata.GetGuid($module.Mvid);if($diskMvid -ne $assembly.ManifestModule.ModuleVersionId){throw 'Loaded engine differs from held engine image'}}finally{$pe.Dispose();$engineStream.Position=0}
  $engine=[ordered]@{assemblyPath=$assembly.Location;assemblySha256=Get-AiwProofHash $engineStream;assemblyVersion=$assembly.GetName().Version.ToString();moduleVersionId=$assembly.ManifestModule.ModuleVersionId.ToString()}
  $env:PSModulePath=$fixedHome+'\Modules;C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
  foreach($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility','Microsoft.WSMan.Management','CimCmdlets','Appx','Dism','Microsoft.PowerShell.LocalAccounts','ScheduledTasks')){Import-Module $module -SkipEditionCheck -Global -ErrorAction Stop}
  $compat=@(Get-PSSession|Where-Object Name -eq 'WinPSCompatSession')
  if($compat.Count -ne 0){throw 'Windows compatibility session forbidden'}
  foreach($name in $caps){
   $command=Get-Command $name -ErrorAction Stop
   if($name -ceq 'New-PSSession'){if($command.CommandType -ne 'Cmdlet' -or $command.ImplementingType.Assembly.Location -ine ($fixedHome+'\System.Management.Automation.dll')){throw 'Native remoting cmdlet required'};continue}
   # Core exposes CimCmdlets from its binary in PSHOME, outside Modules.
   # Accept that exact native command image, not arbitrary PSHOME modules/proxies.
   if($name -ceq 'Get-CimInstance'){
    $cimImage=$fixedHome+'\Microsoft.Management.Infrastructure.CimCmdlets.dll'
    if($command.CommandType -ne 'Cmdlet' -or !$command.Module -or $command.ModuleName -cne 'CimCmdlets' -or $command.Module.Path -ine $cimImage -or $command.ImplementingType.Assembly.Location -ine $cimImage){throw 'Exact native CIM cmdlet required'}
    continue
   }
   if($command.CommandType -notin @('Cmdlet','Function') -or !$command.Module -or $command.Module.Path -notlike ($fixedHome+'\Modules\*') -and $command.Module.Path -notlike 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\*'){throw ('Native capability unavailable: '+$name)}
   if($command.CommandType -eq 'Function' -and $command.ModuleName -cne 'ScheduledTasks'){throw ('Unexpected remoting proxy capability: '+$name)}
  }
  $common=New-AiwRuntimeCommonIdentity $PSVersionTable.PSEdition $PSVersionTable.PSVersion.ToString() ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()) $PSHOME $engine $caps $compat.Count

  if($Kind -ceq 'Direct'){
   $direct=New-AiwDirectRuntimeIdentity $common $exe (Get-AiwProofHash $exeStream)
   Assert-AiwRuntimeObservation $direct Direct
   return $direct
  }
  $configurationName=[string]$PSSenderInfo.ConfigurationName
  if($configurationName -cne 'PowerShell.7.6'){throw 'Actual WSMan configuration name mismatch'}
  $registry=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  try{$pluginKey=$registry.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\'+$configurationName,$false);if(!$pluginKey){throw 'WSMan plugin registration absent'};try{$configXml=[string]$pluginKey.GetValue('ConfigXML',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}finally{$pluginKey.Dispose()}}finally{$registry.Dispose()}
  if([string]::IsNullOrWhiteSpace($configXml)){throw 'WSMan configuration XML absent'}
  $registration=Assert-AiwWsmanConfiguration -ConfigXml $configXml -RuntimeVersion $PSVersionTable.PSVersion.ToString() -ConfigurationOnly
  $pluginPath=$registration.pluginPath;$uri=$registration.resourceUri
  $pluginStream=Open-AiwProofFile $pluginPath;$referencePlugin=Open-AiwProofFile ($fixedHome+'\pwrshplugin.dll')
  $pluginHash=Get-AiwProofHash $pluginStream
  if($pluginHash -cne (Get-AiwProofHash $referencePlugin)){throw 'Registered plugin differs from machine runtime'}
  $loaded=@([Diagnostics.Process]::GetCurrentProcess().Modules|Where-Object {$_.FileName -ieq $pluginPath})
  if($loaded.Count -ne 1){throw 'Registered plugin is not the loaded WSMan plugin'}
  $startupPath=[IO.Path]::Combine([IO.Path]::GetDirectoryName($pluginPath),'RemotePowerShellConfig.txt')
  $startupStream=Open-AiwProofFile $startupPath;$startupHash=Get-AiwProofHash $startupStream
  if($startupStream.Length -gt 8192){throw 'WSMan startup configuration length invalid'}
  $textReader=[IO.StreamReader]::new($startupStream,[Text.Encoding]::UTF8,$true,1024,$true)
  try{$startup=$textReader.ReadToEnd()}finally{$textReader.Dispose();$startupStream.Position=0}
  [void](Assert-AiwWsmanConfiguration -ConfigXml $configXml -StartupText $startup -RuntimeVersion $PSVersionTable.PSVersion.ToString())
  $wsman=[ordered]@{};foreach($key in $common.Keys){$wsman[$key]=$common[$key]}
  $wsman.configurationName=$configurationName;$wsman.hostKind='WSMan';$wsman.hostExecutable=$exe;$wsman.hostExecutableSha256=Get-AiwProofHash $exeStream
  $wsman.pluginPath=$pluginPath;$wsman.pluginSha256=$pluginHash;$wsman.configurationSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($configXml))).ToLowerInvariant();$wsman.startupConfigSha256=$startupHash;$wsman.resourceUri=$uri;$wsman.configurationPsHome=$fixedHome;$wsman.configurationCoreclrDir=$fixedHome
  Assert-AiwRuntimeObservation $wsman WSMan
  if([string]::IsNullOrWhiteSpace($DirectProofSource)){throw 'Independently compiled direct proof required'}
  $childImage=Open-AiwProofFile ($fixedHome+'\pwsh.exe')
  $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$fixedHome+'\pwsh.exe';$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  foreach($argument in @('-NoLogo','-NoProfile','-NonInteractive','-Command','& ([scriptblock]::Create([Console]::In.ReadToEnd()))')){[void]$info.ArgumentList.Add($argument)}
  $child=[Diagnostics.Process]::new();$child.StartInfo=$info
  try{
   if(!$child.Start()){throw 'Direct engine observer could not start'}
   $outBuffer=[char[]]::new(4096);$errBuffer=[char[]]::new(4096)
   $outText=[Text.StringBuilder]::new();$errText=[Text.StringBuilder]::new()
   $stdout=$child.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length);$stderr=$child.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)
   $outDone=$false;$errDone=$false
   $inputText='& { '+$DirectProofSource+' } Direct | ConvertTo-Json -Depth 12 -Compress'
   $inputWrite=$child.StandardInput.WriteAsync($inputText)
   $watch=[Diagnostics.Stopwatch]::StartNew();$inputClosed=$false
   while(!$child.HasExited -or !$outDone -or !$errDone -or !$inputClosed){
    if($watch.ElapsedMilliseconds -ge 45000){try{$child.Kill($true)}catch{};throw 'Direct engine observer timed out'}
    if(!$inputClosed -and $inputWrite.IsCompleted){[void]$inputWrite.GetAwaiter().GetResult();$child.StandardInput.Close();$inputClosed=$true}
    if(!$outDone -and $stdout.IsCompleted){$count=$stdout.GetAwaiter().GetResult();if($count -eq 0){$outDone=$true}else{[void]$outText.Append($outBuffer,0,$count);if($outText.Length -gt 1048576){try{$child.Kill($true)}catch{};throw 'Direct engine observer output exceeded bound'};$stdout=$child.StandardOutput.ReadAsync($outBuffer,0,$outBuffer.Length)}}
    if(!$errDone -and $stderr.IsCompleted){$count=$stderr.GetAwaiter().GetResult();if($count -eq 0){$errDone=$true}else{[void]$errText.Append($errBuffer,0,$count);if($errText.Length -gt 65536){try{$child.Kill($true)}catch{};throw 'Direct engine observer error output exceeded bound'};$stderr=$child.StandardError.ReadAsync($errBuffer,0,$errBuffer.Length)}}
    [Threading.Thread]::Sleep(10)
   }
   $output=$outText.ToString();$errorOutput=$errText.ToString()
   if($child.ExitCode -ne 0 -or ![string]::IsNullOrWhiteSpace($errorOutput)){throw 'Direct engine observer failed'}
   $worker=ConvertFrom-Json -InputObject $output -AsHashtable
  }finally{try{if(!$child.HasExited){$child.Kill($true)}}catch{};$child.Dispose()}
  Assert-AiwRuntimeObservation $worker Direct
  foreach($key in @('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')){if($worker.engine[$key] -cne $engine[$key]){throw 'WSMan engine differs from independently observed direct engine'}}
  if($worker.version -cne $wsman.version -or $worker.executableSha256 -cne (Get-AiwProofHash $childImage)){throw 'Direct worker runtime differs from held runtime'}
  # Keep file handles alive for this WSMan runspace, including subsequent Copy-Item.
  if(!$ExecutionContext.SessionState.PSVariable.Get('global:AiwRuntimeProofHandles')){$global:AiwRuntimeProofHandles=[Collections.Generic.List[IO.FileStream]]::new()}
  foreach($stream in $held){$global:AiwRuntimeProofHandles.Add($stream)};$held.Clear()
  return [ordered]@{wsman=$wsman;worker=$worker}
 }finally{foreach($stream in $held){$stream.Dispose()}}
}
function Assert-AiwRuntimeBinding($Observed,$Expected) {
 if($null -eq $Expected){throw 'Missing approved PowerShell runtime identity; new setup/baseline approval required'}
 foreach($field in @('edition','version','prerelease','architecture','executable','psHome','executableSha256','compatibilitySessionCount')){if([string]$Observed.$field -cne [string]$Expected.$field){throw ('Approved PowerShell runtime differs: '+$field)}}
 if(($Observed.capabilities -join '|') -cne ($Expected.capabilities -join '|')){throw 'Approved native runtime capabilities differ'}
 foreach($field in @('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')){if(!$Expected.engine -or [string]$Observed.engine.$field -cne [string]$Expected.engine.$field){throw ('Approved loaded engine differs: '+$field)}}
}
function Select-AiwRuntimeIdentity($Runtime) {
 [ordered]@{edition=$Runtime.edition;version=$Runtime.version;prerelease=$Runtime.prerelease;architecture=$Runtime.architecture;executable=$Runtime.executable;psHome=$Runtime.psHome;executableSha256=$Runtime.executableSha256;capabilities=@($Runtime.capabilities);compatibilitySessionCount=[int]$Runtime.compatibilitySessionCount;engine=[ordered]@{assemblyPath=$Runtime.engine.assemblyPath;assemblySha256=$Runtime.engine.assemblySha256;assemblyVersion=$Runtime.engine.assemblyVersion;moduleVersionId=$Runtime.engine.moduleVersionId}}
}
function Select-AiwWsmanIdentity($Runtime) {
 $result=[ordered]@{}
 foreach($field in @('configurationName','hostKind','hostExecutable','hostExecutableSha256','edition','version','prerelease','architecture','psHome','pluginPath','pluginSha256','configurationSha256','startupConfigSha256','resourceUri','configurationPsHome','configurationCoreclrDir','compatibilitySessionCount')){$result[$field]=$Runtime.$field}
 $result.capabilities=@($Runtime.capabilities)
 $result.engine=[ordered]@{assemblyPath=$Runtime.engine.assemblyPath;assemblySha256=$Runtime.engine.assemblySha256;assemblyVersion=$Runtime.engine.assemblyVersion;moduleVersionId=$Runtime.engine.moduleVersionId}
 $result
}
function Assert-AiwWsmanBinding($Observed,$Expected) {
 if(!$Expected){throw 'Missing approved WSMan endpoint identity; preserve historical preparation'}
 foreach($field in @('configurationName','hostKind','hostExecutable','hostExecutableSha256','edition','version','prerelease','architecture','psHome','pluginPath','pluginSha256','configurationSha256','startupConfigSha256','resourceUri','configurationPsHome','configurationCoreclrDir','compatibilitySessionCount')){if([string]$Observed.$field -cne [string]$Expected.$field){throw ('Approved WSMan identity differs: '+$field)}}
 if(($Observed.capabilities -join '|') -cne ($Expected.capabilities -join '|')){throw 'Approved WSMan native capabilities differ'}
 foreach($field in @('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')){if([string]$Observed.engine.$field -cne [string]$Expected.engine.$field){throw ('Approved WSMan engine differs: '+$field)}}
}
$hostRuntime=& $runtimeProof

function Write-AiwTransportReceipt {
 param([Parameter(ValueFromPipeline,Mandatory)]$Record)
 process {
  # The same session keeps its image/startup files held. Recheck mutable registry
  # registration after the operation before publishing its successful receipt.
  Invoke-Command -Session $session -ArgumentList $endpointRuntime.configurationSha256 -ScriptBlock {
   param($expected)
   $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\PowerShell.7.6',$false)
   if(!$key){throw 'WSMan registration disappeared'}
   try{$xml=[string]$key.GetValue('ConfigXML',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}finally{$key.Dispose()}
   $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($xml))).ToLowerInvariant()
   if($hash -cne $expected -or $PSSenderInfo.ConfigurationName -cne 'PowerShell.7.6'){throw 'WSMan registration changed during operation; retain lease'}
  } | Out-Null
  $Record | Add-Member -NotePropertyName powerShellRuntime -NotePropertyValue $workerRuntime -Force
  $Record | Add-Member -NotePropertyName powerShellEndpoint -NotePropertyValue $endpointRuntime -Force
  $Record | ConvertTo-Json -Depth 16 -Compress
 }
}
$session=$null;$credential=$null
try {
 $tools=Join-Path $Workspace 'tools'
 $prepared=Get-Content -LiteralPath (Join-Path $tools 'msix-preparation.json') -Raw|ConvertFrom-Json
 $request=Get-Content -LiteralPath (Join-Path $tools 'request.json') -Raw|ConvertFrom-Json
 if($prepared.runId -cne $RunId -or $request.runId -cne $RunId -or $request.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'){throw 'Prepared run identity differs'}
 if(!$prepared.PSObject.Properties['powerShellRuntime'] -or !$request.PSObject.Properties['powerShellRuntime'] -or !$prepared.powerShellRuntime -or !$request.powerShellRuntime){throw 'Legacy prepared workspace has no approved PowerShell 7.6 binding; preserve evidence and obtain a fresh baseline approval'}
 if($prepared.powerShellRuntime.endpoint -cne 'PowerShell.7.6' -or $request.powerShellRuntime.endpoint -cne 'PowerShell.7.6'){throw 'Approved PowerShell.7.6 endpoint required'}
 if(!$prepared.powerShellRuntime.PSObject.Properties['wsman'] -or !$request.powerShellRuntime.PSObject.Properties['wsman'] -or !$prepared.powerShellRuntime.wsman -or !$request.powerShellRuntime.wsman){throw 'Historical runtime binding has no approved WSMan identity; do not execute'}
 Assert-AiwRuntimeBinding $hostRuntime $prepared.powerShellRuntime.host
 Assert-AiwRuntimeBinding $hostRuntime $request.powerShellRuntime.host
 $trusted=Get-Item -LiteralPath 'Cert:\CurrentUser\Root\BC14DCC4E37F83161EBB55AF8624E36A79E19256'
 if($trusted.Thumbprint -cne $prepared.worker.httpsCertificateSha1 -or $trusted.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){throw 'Enrolled worker certificate expired or differs'}
 $stored=Import-Clixml -LiteralPath (Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml')
 $credential=[pscredential]::new('labadmin',$stored.Password);$stored=$null
 # The actual credential-bearing channel validates chain, name and expiry normally.
 $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName PowerShell.7.6 -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
 $remote=Invoke-Command -Session $session -ScriptBlock $runtimeProof -ArgumentList 'WSMan',$runtimeProof.ToString()
 $workerRuntime=Select-AiwRuntimeIdentity $remote.worker
 $endpointRuntime=Select-AiwWsmanIdentity $remote.wsman
 Assert-AiwWsmanBinding $endpointRuntime $prepared.powerShellRuntime.wsman
 Assert-AiwWsmanBinding $endpointRuntime $request.powerShellRuntime.wsman
 Assert-AiwRuntimeBinding $workerRuntime $prepared.powerShellRuntime.worker
 Assert-AiwRuntimeBinding $workerRuntime $request.powerShellRuntime.worker
 $root='C:\ProgramData\AIW\MsixWorker\'+$RunId
 $identity=Invoke-Command -Session $session -ScriptBlock {
  $ErrorActionPreference='Stop'
  $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
  $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){return @{rejected=$true}}
  @{workerUuid=$uuid;actorSid=$actor.User.Value;rejected=$false}
 }
 if($identity.rejected){
  if($Operation -eq 'Ready'){@{fatal=$true;reason='Exact elevated VM107 operator required'}|Write-AiwTransportReceipt;return}
  throw 'Exact elevated VM107 operator required'
 }
 if($Operation -eq 'Ready'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce,$request.workerUuid -ScriptBlock {
   param($root,$nonce,$uuid)
   $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
   try {
    $account=Get-Content -LiteralPath ($root+'\account.json') -Raw|ConvertFrom-Json
    $user=Get-LocalUser -Name AiwStandardUser
    if($account.runNonce -cne $nonce -or $account.workerUuid -cne $uuid -or !$account.created -or $user.SID.Value -cne $account.userSid -or $user.SID.Value -ceq 'S-1-5-21-3556347314-2314855617-1438300668-1001'){throw 'Run-owned account differs'}
    $result=@{nonce=$nonce;workerUuid=$uuid;userSid=$account.userSid;accountBound=$true;ready=$false;active=$false;profileLoaded=$false;sessionId=0}
    $sessions=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object {
     $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid
     if($owner.ReturnValue -ne 0){throw 'Explorer owner query failed'}
     $owner.Sid -ceq $account.userSid
    }|Select-Object -ExpandProperty SessionId -Unique)
    if($sessions.Count -gt 1 -or ($sessions.Count -eq 1 -and $sessions[0] -le 0)){throw 'Contradictory standard-user session'}
    if($sessions.Count -eq 0){return $result}
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AiwReadiness {
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server,int session,int kind,out IntPtr value,out int bytes);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
 public static bool Active(int session) {
  IntPtr value;int bytes;
  if(!WTSQuerySessionInformationW(IntPtr.Zero,session,8,out value,out bytes))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try{if(bytes!=4 || value==IntPtr.Zero)throw new InvalidOperationException("Session state buffer differs");return Marshal.ReadInt32(value)==0;}finally{WTSFreeMemory(value);}
 }
}
'@
    $profile=@(Get-CimInstance Win32_UserProfile|Where-Object SID -CEQ $account.userSid)
    if($profile.Count -gt 1){throw 'Ambiguous loaded profile'}
    $result.sessionId=[int]$sessions[0];$result.active=[AiwReadiness]::Active($result.sessionId)
    $result.profileLoaded=($profile.Count -eq 1 -and $profile[0].Loaded)
    $result.ready=($result.active -and $result.profileLoaded)
    $result
   }catch{@{fatal=$true;nonce=$nonce;workerUuid=$uuid;reason=$_.Exception.Message}}
  }|Write-AiwTransportReceipt;return
 }
 if($Operation -eq 'Clean'){
  $clean=Invoke-Command -Session $session -ScriptBlock {
   $ErrorActionPreference='Stop'
   $expected=@('Administrator','CodexSandboxOffline','CodexSandboxOnline','DefaultAccount','Guest','labadmin','WDAGUtilityAccount')|Sort-Object
   if((@(Get-LocalUser|Select-Object -ExpandProperty Name|Sort-Object)-join '|') -cne ($expected -join '|')){throw 'Restored account inventory differs'}
   foreach($path in @('C:\ProgramData\AIW\MsixWorker','C:\AIW-Worker107-Research-r1','C:\AIW-Worker107-Intake-r1','C:\AIW-Msix-Lifecycle-Input','C:\Users\AiwStandardUser')){if(Test-Path -LiteralPath $path){throw 'Restored worker contains trial artifacts'}}
   if(@(Get-AppxPackage -AllUsers -Name 'AIWResearch.NotepadPP').Count -ne 0 -or @(Get-AppxProvisionedPackage -Online|Where-Object DisplayName -CEQ 'AIWResearch.NotepadPP').Count -ne 0 -or @(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Restored package/process inventory not empty'}
   if(@(Get-ScheduledTask|Where-Object TaskName -Match '^AIW').Count -ne 0){throw 'Restored worker has AIW tasks'}
   $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
   try{if($key.GetValueNames() -contains 'DefaultPassword' -or $key.GetValueNames() -contains 'AutoLogonCount' -or $key.GetValue('AutoAdminLogon') -eq '1'){throw 'Automatic sign-in remains'}}finally{$key.Dispose()}
   $listeners=@(Get-ChildItem WSMan:\localhost\Listener)
   if($listeners.Count -ne 1){throw 'Expected sole HTTPS listener'}
   $settings=Get-ChildItem $listeners[0].PSPath
   if(($settings|Where-Object Name -EQ Transport).Value -cne 'HTTPS' -or ($settings|Where-Object Name -EQ CertificateThumbprint).Value -cne 'BC14DCC4E37F83161EBB55AF8624E36A79E19256'){throw 'Listener differs'}
   @{clean=$true;workerUuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;accounts=$expected;trialArtifactsAbsent=$true;automaticSignInDisabled=$true}
  }
  $clean|Write-AiwTransportReceipt;return
 }
 if($Operation -eq 'Stage'){
  Invoke-Command -Session $session -ArgumentList $root -ScriptBlock {
   param($root)
   $ErrorActionPreference='Stop'
   function New-AiwProtectedDirectory([string]$Path,[Security.AccessControl.DirectorySecurity]$Acl) {
    if(Test-Path -LiteralPath $Path){throw 'Fresh protected directory required'}
    # ACL is supplied at creation; there is no inherited-ACL exposure window.
    $null=[IO.FileSystemAclExtensions]::CreateDirectory($Acl,$Path)
    $item=Get-Item -LiteralPath $Path -Force
    $actual=Get-Acl -LiteralPath $Path
    if(!$item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or !$actual.AreAccessRulesProtected -or $actual.GetSecurityDescriptorSddlForm('Access,Owner') -cne $Acl.GetSecurityDescriptorSddlForm('Access,Owner')){throw 'Created protected directory identity or ACL differs'}
   }
   $base='C:\ProgramData\AIW\MsixWorker'
   if(Test-Path -LiteralPath $base){throw 'Existing worker intake refused; cold recovery required'}
   $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-21-3556347314-2314855617-1438300668-1001'))
   foreach($sid in @('S-1-5-18','S-1-5-21-3556347314-2314855617-1438300668-1001')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
   $parent='C:\ProgramData\AIW'
   if(!(Test-Path -LiteralPath $parent)){New-AiwProtectedDirectory $parent $acl}
   $parentItem=Get-Item -LiteralPath $parent
   $parentAcl=Get-Acl -LiteralPath $parent
   if($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or !$parentAcl.AreAccessRulesProtected){throw 'Protected ordinary worker parent required'}
   foreach($rule in $parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-21-3556347314-2314855617-1438300668-1001')){throw 'Worker parent ACL differs'}}
   if(Test-Path -LiteralPath $root){throw 'Existing run intake refused'}
   New-AiwProtectedDirectory $base $acl;New-AiwProtectedDirectory $root $acl;New-AiwProtectedDirectory ($root+'\input') $acl
  }
  Copy-Item -LiteralPath (Join-Path $tools 'agent.exe') -Destination ($root+'\agent.exe') -ToSession $session
  Copy-Item -LiteralPath (Join-Path $tools 'request.json') -Destination ($root+'\request.json') -ToSession $session
  foreach($name in @('assembly.json','signing.json')){Copy-Item -LiteralPath (Join-Path $tools $name) -Destination ($root+'\input\'+$name) -ToSession $session}
  Copy-Item -LiteralPath $prepared.packageImport.payload.finalPath -Destination ($root+'\input\application.msix') -ToSession $session
  Invoke-Command -Session $session -ArgumentList $root,$request -ScriptBlock {
   param($root,$request)
   $ErrorActionPreference='Stop'
   foreach($entry in @(@('agent.exe',$request.agentSha256),@('input\application.msix',$request.packageSha256),@('input\assembly.json',$request.assemblySha256),@('input\signing.json',$request.signingSha256))){if((Get-FileHash -LiteralPath (Join-Path $root $entry[0])).Hash.ToLowerInvariant() -cne $entry[1]){throw 'Transferred approved bytes differ'}}
   @{staged=$true;nonce=$request.nonce}
  }|Write-AiwTransportReceipt;return
 }
 if($Operation -eq 'Restart'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $enrolled=Get-Content -LiteralPath ($root+'\enroll-result.json') -Raw|ConvertFrom-Json
   if($enrolled.runNonce -cne $nonce -or !$enrolled.restartRequired){throw 'Run-owned enrollment required'}
   $marker=[IO.File]::Open(($root+'\restart-intent'),[IO.FileMode]::CreateNew);$marker.Flush($true);$marker.Dispose()
   # Schedule reboot after the successful dispatch reply has left WinRM.
   & C:\Windows\System32\shutdown.exe /r /t 5 /f | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Restart dispatch failed'}
   @{restartDispatched=$true;nonce=$nonce}
  }|Write-AiwTransportReceipt;return
 }
 if($Operation -in @('Enroll','Control','Run')){
  $op=$Operation.ToLowerInvariant()
  Invoke-Command -Session $session -ArgumentList $root,$op,$RunId,$request.agentSha256,$request.nonce -ScriptBlock {
   param($root,$op,$runId,$agentSha,$nonce)
   $ErrorActionPreference='Stop'
   $marker=$root+'\'+$op+'-dispatch.json'
   if(Test-Path -LiteralPath $marker){throw 'Operation already dispatched; inspect status, never replay'}
   if((Get-FileHash -LiteralPath ($root+'\agent.exe')).Hash.ToLowerInvariant() -cne $agentSha){throw 'Approved agent differs'}
   $source=@'
#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
foreach($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','CimCmdlets')){Import-Module $module -SkipEditionCheck -ErrorAction Stop}
if($PSVersionTable.PSVersion.ToString() -match '-' -or [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName -ine 'C:\Program Files\PowerShell\7\pwsh.exe' -or $PSHOME -ine 'C:\Program Files\PowerShell\7'){throw 'Exact stable machine PowerShell runtime required'}
$root=$PSScriptRoot
$request=Get-Content -LiteralPath ($root+'\request.json') -Raw|ConvertFrom-Json
if(!$request.PSObject.Properties['powerShellRuntime'] -or !$request.powerShellRuntime -or $request.powerShellRuntime.worker.version -cne $PSVersionTable.PSVersion.ToString() -or $request.powerShellRuntime.worker.executableSha256 -cne (Get-FileHash -LiteralPath 'C:\Program Files\PowerShell\7\pwsh.exe').Hash.ToLowerInvariant()){throw 'SYSTEM runtime differs from approved request'}
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $request.workerUuid -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'Exact SYSTEM worker required'}
if((Get-FileHash -LiteralPath ($root+'\agent.exe')).Hash.ToLowerInvariant() -cne $request.agentSha256){throw 'Agent differs'}
$p=[Diagnostics.Process]::new();$p.StartInfo=[Diagnostics.ProcessStartInfo]::new(($root+'\agent.exe'),'@@OP@@ '+$request.runId)
$p.StartInfo.UseShellExecute=$false;$p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true;$p.StartInfo.CreateNoWindow=$true
try {
 if(!$p.Start()){throw 'Native worker did not start'}
 $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
 if(!$p.WaitForExit(1320000)){throw 'Native worker deadline exceeded'}
 [IO.File]::WriteAllText(($root+'\@@OP@@-stdout.txt'),$out.GetAwaiter().GetResult())
 [IO.File]::WriteAllText(($root+'\@@OP@@-stderr.txt'),$err.GetAwaiter().GetResult())
 $record=@{completed=$true;exitCode=$p.ExitCode;nonce=$request.nonce;operation='@@OP@@'}
 $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Compress))
 $path=$root+'\@@OP@@-transport.json';$pending=$path+'.pending'
 $f=[IO.File]::Open($pending,[IO.FileMode]::CreateNew)
 try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
 [IO.File]::Move($pending,$path)
}finally{$p.Dispose()}
'@
   $path=$root+'\'+$op+'-task.ps1';[IO.File]::WriteAllText($path,$source.Replace('@@OP@@',$op),[Text.UTF8Encoding]::new($false))
   $service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\');$name='AIW-Msix-'+$op+'-'+$runId
   if(@($folder.GetTasks(1)|Where-Object Name -CEQ $name).Count -ne 0){throw 'Fresh task required'}
   $task=$service.NewTask(0);$task.Principal.UserId='S-1-5-18';$task.Principal.LogonType=5;$task.Principal.RunLevel=1;$task.Settings.ExecutionTimeLimit='PT24M'
   $task.Settings.DisallowStartIfOnBatteries=$false;$task.Settings.StopIfGoingOnBatteries=$false
   $action=$task.Actions.Create(0);$action.Path='C:\Program Files\PowerShell\7\pwsh.exe';$action.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$path+'"'
   $registered=$folder.RegisterTaskDefinition($name,$task,0x12,'S-1-5-18',$null,5,'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-3556347314-2314855617-1438300668-1001)')
   $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{nonce=$nonce;operation=$op}|ConvertTo-Json -Compress));$f=[IO.File]::Open($marker,[IO.FileMode]::CreateNew)
   try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
   $null=$registered.RunEx($null,0,0,$null)
   @{dispatched=$true;nonce=$nonce;operation=$op}
  }|Write-AiwTransportReceipt;return
 }
 if($Operation -eq 'Status'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $records=[ordered]@{}
   foreach($name in @('enroll-transport','control-transport','run-transport','enroll-result','control-result','result','failure','logon-cleared')){
    $path=$root+'\'+$name+'.json';if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path).Length -gt 262144){throw 'Status bound exceeded'};$records[$name]=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json}
   }
   @{nonce=$nonce;records=$records}
  }|Write-AiwTransportReceipt;return
 }
 if($Operation -eq 'Collect'){
  Invoke-Command -Session $session -ArgumentList $root,$request.nonce -ScriptBlock {
   param($root,$nonce)
   $ErrorActionPreference='Stop';$files=@();$total=0
   # Read-only retry is safe only after native/controller work has stopped.
   if(@(Get-ScheduledTask|Where-Object {$_.TaskName -like 'AIW-Msix-*' -and $_.State -in @('Running','Queued')}).Count -ne 0 -or @(Get-Process -Name 'notepad++','agent' -ErrorAction SilentlyContinue).Count -ne 0){throw 'Worker running or queued; preserve its lease and evidence'}
   # Source custody is independent of the controller's optional/partial copies.
   if(-not ('AiwRawTree' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class AiwRawTree : IDisposable {
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint attr;public System.Runtime.InteropServices.ComTypes.FILETIME c,a,w;public uint volume,high,low,links,indexHigh,indexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 readonly List<IDisposable> held=new List<IDisposable>();
 readonly Dictionary<string,string[]> directories=new Dictionary<string,string[]>();
 readonly Dictionary<string,FileStream> files=new Dictionary<string,FileStream>();
 readonly string root;
 public AiwRawTree(string path) {
  root=Path.GetFullPath(path);
  try { var parents=new Stack<string>();for(var p=root;p!=null;p=Path.GetDirectoryName(p))parents.Push(p);while(parents.Count!=0)HoldDirectory(parents.Pop());Walk(root,0); }catch{Dispose();throw;}
 }
 void HoldDirectory(string path) {
  var h=CreateFileW(@"\\?\"+Path.GetFullPath(path),0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  held.Add(h);Info i;if(h.IsInvalid || !GetFileInformationByHandle(h,out i) || (i.attr&0x410)!=0x10)throw new IOException("Ordinary held evidence directory required");
 }
 static string[] Entries(string path) {return Directory.GetFileSystemEntries(path).OrderBy(p=>p,StringComparer.Ordinal).ToArray();}
 void Walk(string path,int depth) {
  if(depth>16 || directories.Count+files.Count>=512)throw new IOException("Raw evidence tree bound exceeded");
  var entries=Entries(path);directories.Add(path,entries);
  foreach(var entry in entries) {
   if(directories.Count+files.Count>=512)throw new IOException("Raw evidence entry count exceeded");
   var attr=File.GetAttributes(entry);if((attr&FileAttributes.ReparsePoint)!=0)throw new IOException("Raw evidence reparse entry refused");
   if((attr&FileAttributes.Directory)!=0){HoldDirectory(entry);Walk(entry,depth+1);continue;}
   var f=new FileStream(entry,FileMode.Open,FileAccess.Read,FileShare.Read);held.Add(f);
   Info i;if(!GetFileInformationByHandle(f.SafeFileHandle,out i) || i.links!=1 || (i.attr&0x410)!=0 || f.Length>4194304)throw new IOException("Raw evidence file identity/bound rejected");
   files.Add(entry.Substring(root.Length+1).Replace('\\','/'),f);
  }
 }
 public string[] Names {get{return files.Keys.OrderBy(p=>p,StringComparer.Ordinal).ToArray();}}
 public byte[] Read(string name) {
  var f=files[name];var data=new byte[checked((int)f.Length)];f.Position=0;int offset=0;
  while(offset<data.Length){int n=f.Read(data,offset,data.Length-offset);if(n==0)throw new EndOfStreamException();offset+=n;}return data;
 }
 public void Verify() {foreach(var d in directories)if(!d.Value.SequenceEqual(Entries(d.Key)))throw new IOException("Raw evidence entries changed during export");}
 public void Dispose() {for(int i=held.Count-1;i>=0;i--)held[i].Dispose();held.Clear();}
}
'@
   }
   $rawEvidence=@{complete=$true;source='runOwnedProfile';nonce=$nonce;present=$false;userSid=$null;files=@()}
   $accountPath=Join-Path $root 'account.json'
   if(Test-Path -LiteralPath $accountPath){
    $account=Get-Content -LiteralPath $accountPath -Raw|ConvertFrom-Json
    if($account.runNonce -cne $nonce -or $account.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $account.userSid -cnotmatch '\AS-1-5-21-3556347314-2314855617-1438300668-[0-9]+\z' -or $account.userSid -ceq 'S-1-5-21-3556347314-2314855617-1438300668-1001'){throw 'Raw evidence account binding differs'}
    $rawEvidence.userSid=$account.userSid
    $profiles=@(Get-CimInstance Win32_UserProfile|Where-Object SID -CEQ $account.userSid)
    if($profiles.Count -gt 1){throw 'Ambiguous raw evidence profile'}
    if($profiles.Count -eq 1){
     if(([IO.Path]::GetFullPath($profiles[0].LocalPath)) -cnotmatch '\A[A-Za-z]:\\'){throw 'Local worker profile required'}
     $source=Join-Path $profiles[0].LocalPath ('AppData\Local\AIW\msix-'+$nonce)
     if(Test-Path -LiteralPath $source){
      $rawEvidence.present=$true;$raw=[AiwRawTree]::new($source)
      try {
       foreach($name in $raw.Names){
        # The stream API needs an extended, canonical Win32 path even when
        # ordinary Core/.NET file reads already support the same long path.
        $streamPath='\\?\'+[IO.Path]::GetFullPath((Join-Path $source $name))
        if(@(Get-Item -LiteralPath $streamPath -Stream '*' -ErrorAction Stop|Where-Object Stream -CNE ':$DATA').Count -ne 0){throw 'Named raw evidence stream refused'}
        $bytes=$raw.Read($name);$hash=[Security.Cryptography.SHA256]::Create()
        try{$sha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
        $total+=$bytes.Length;if($total -gt 16MB -or $files.Count -ge 512){throw 'Evidence export bound exceeded'}
        $entry=@{path=('raw/'+$name);sha256=$sha;bytes=$bytes.Length}
        $rawEvidence.files+=$entry
        $files+=@{path=$entry.path;sha256=$sha;bytes=$bytes.Length;base64=[Convert]::ToBase64String($bytes)}
       }
       $raw.Verify()
      }finally{$raw.Dispose()}
     }
    }
   }
   if(!$rawEvidence.present -and (@('run-dispatch.json','run-started.json','result.json')|Where-Object {Test-Path -LiteralPath (Join-Path $root $_)})){throw 'Dispatched application authoritative raw evidence absent; preserve lease'}
   # Only receipts, raw evidence and bounded diagnostic logs; never inputs/account secrets.
   $exportFiles=@()
   if(Test-Path -LiteralPath $root){
    if((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence root refused'}
    $exportFiles+=@(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction Stop)
    foreach($directory in @(($root+'\evidence'),($root+'\failed-evidence'))){
     if(Test-Path -LiteralPath $directory){
      if((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse evidence directory refused'}
      $tree=@(Get-ChildItem -LiteralPath $directory -Recurse -Force -ErrorAction Stop)
      if(@($tree|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count -ne 0){throw 'Reparse evidence entry refused'}
      $exportFiles+=@($tree|Where-Object {!$_.PSIsContainer})
     }
    }
   }
   foreach($file in $exportFiles){
    $name=$file.FullName.Substring($root.Length+1).Replace('\','/')
    if($name -notmatch '\A(?:evidence/|failed-evidence/|[^/]+\.(?:json|txt)\z)' -or $name -in @('request.json','account.json')){continue}
    if($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -gt 4MB){throw 'Evidence file bound/type rejected'}
    $total+=$file.Length;if($total -gt 16MB -or $files.Count -ge 512){throw 'Evidence export bound exceeded'}
    $bytes=[IO.File]::ReadAllBytes($file.FullName);$hash=[Security.Cryptography.SHA256]::Create()
    try{$sha=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $files+=@{path=$name;sha256=$sha;bytes=$bytes.Length;base64=[Convert]::ToBase64String($bytes)}
   }
   @{nonce=$nonce;files=$files;quiescent=$true;enumerationComplete=$true;rawEvidence=$rawEvidence}
  }|Write-AiwTransportReceipt;return
 }
 throw 'Unsupported closed transport operation'
}finally{if($session){Remove-PSSession $session};$credential=$null}
