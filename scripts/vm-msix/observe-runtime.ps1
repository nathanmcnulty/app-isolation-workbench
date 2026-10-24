#Requires -Version 7.6
#Requires -PSEdition Core
# Read-only fixed identity/capability observation. Never configures endpoints or a VM.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest;$ProgressPreference='SilentlyContinue'
# Runtime proof is fixed source, reused locally and on the explicit endpoint.
$runtimeProof = {
 $ErrorActionPreference='Stop';$global:PSModuleAutoLoadingPreference='None'
 if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc') -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64'){throw 'Stable x64 PowerShell Core >=7.6 required'}
 $exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
 if($exe -ine 'C:\Program Files\PowerShell\7\pwsh.exe' -or $PSHOME -ine 'C:\Program Files\PowerShell\7'){throw 'Exact machine PowerShell executable and PSHOME required'}
 $env:PSModulePath=($PSHOME+'\Modules;'+$env:WINDIR+'\System32\WindowsPowerShell\v1.0\Modules')
 foreach($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility','Microsoft.WSMan.Management','CimCmdlets','Appx','Dism','Microsoft.PowerShell.LocalAccounts','ScheduledTasks')){Import-Module $module -SkipEditionCheck -Global -ErrorAction Stop}
 $compat=@(Get-PSSession|Where-Object Name -eq 'WinPSCompatSession')
 if($compat.Count -ne 0){throw 'Windows compatibility session forbidden'}
 $caps=@('Add-Type','Get-CimInstance','Get-AppxPackage','Get-AppxPackageManifest','Add-AppxPackage','Remove-AppxPackage','Get-AppxProvisionedPackage','Get-LocalUser','New-LocalUser','Disable-LocalUser','Add-LocalGroupMember','Get-LocalGroupMember','Get-AuthenticodeSignature','Get-ScheduledTask','New-PSSession')
 foreach($name in $caps){
  $command=Get-Command $name -ErrorAction Stop
  if($name -ceq 'New-PSSession'){if($command.CommandType -ne 'Cmdlet' -or $command.ImplementingType.Assembly.Location -ine ($PSHOME+'\System.Management.Automation.dll')){throw 'Native remoting cmdlet required'};continue}
  if($command.CommandType -notin @('Cmdlet','Function') -or !$command.Module -or $command.Module.Path -notlike ($PSHOME+'\Modules\*') -and $command.Module.Path -notlike ($env:WINDIR+'\System32\WindowsPowerShell\v1.0\Modules\*')){throw ('Native capability unavailable: '+$name)}
  if($command.CommandType -eq 'Function' -and $command.ModuleName -cne 'ScheduledTasks'){throw ('Unexpected remoting proxy capability: '+$name)}
 }
 [ordered]@{edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();prerelease='';architecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();executable=$exe;psHome=$PSHOME;executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant();capabilities=$caps;compatibilitySessionCount=$compat.Count}
}
function Assert-AiwRuntimeBinding($Observed,$Expected) {
 if($null -eq $Expected){throw 'Missing approved PowerShell runtime identity; new setup/baseline approval required'}
 foreach($field in @('edition','version','prerelease','architecture','executable','psHome','executableSha256','compatibilitySessionCount')){if([string]$Observed.$field -cne [string]$Expected.$field){throw ('Approved PowerShell runtime differs: '+$field)}}
 if(($Observed.capabilities -join '|') -cne ($Expected.capabilities -join '|')){throw 'Approved native runtime capabilities differ'}
}
function Select-AiwRuntimeIdentity($Runtime) {
 [ordered]@{edition=$Runtime.edition;version=$Runtime.version;prerelease=$Runtime.prerelease;architecture=$Runtime.architecture;executable=$Runtime.executable;psHome=$Runtime.psHome;executableSha256=$Runtime.executableSha256;capabilities=@($Runtime.capabilities);compatibilitySessionCount=[int]$Runtime.compatibilitySessionCount}
}
$hostRuntime=& $runtimeProof

$trusted=Get-Item -LiteralPath 'Cert:\CurrentUser\Root\BC14DCC4E37F83161EBB55AF8624E36A79E19256'
if($trusted.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){throw 'Pinned worker HTTPS certificate expired'}
$session=$null;$credential=$null
try {
 $stored=Import-Clixml -LiteralPath (Join-Path $env:USERPROFILE '.aiw-private\worker107-winrm.xml')
 $credential=[pscredential]::new('labadmin',$stored.Password);$stored=$null
 $session=New-PSSession -ComputerName '192.168.1.174' -UseSSL -Authentication Basic -Credential $credential -ConfigurationName PowerShell.7.6 -SessionOption (New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000)
 $worker=Select-AiwRuntimeIdentity (Invoke-Command -Session $session -ScriptBlock $runtimeProof)
 $identity=Invoke-Command -Session $session -ScriptBlock {
  $ErrorActionPreference='Stop'
  $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
  $actor=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($uuid -ine 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or $actor.User.Value -cne 'S-1-5-21-3556347314-2314855617-1438300668-1001' -or !([Security.Principal.WindowsPrincipal]::new($actor)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Exact elevated VM107 operator required'}
  $uuid
 }
 @{workerUuid=$identity;endpoint='PowerShell.7.6';host=$hostRuntime;worker=$worker}|ConvertTo-Json -Depth 6 -Compress
}finally{if($session){Remove-PSSession $session};$credential=$null}
