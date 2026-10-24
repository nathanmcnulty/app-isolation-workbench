#Requires -Version 7.6
#Requires -PSEdition Core
# The exact block is shared by direct launches and the read-only WSMan observer.
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
    if(!$inputClosed -and $inputWrite.IsCompleted){$inputWrite.GetAwaiter().GetResult();$child.StandardInput.Close();$inputClosed=$true}
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
$AiwPowerShellRuntime=& $runtimeProof Direct
