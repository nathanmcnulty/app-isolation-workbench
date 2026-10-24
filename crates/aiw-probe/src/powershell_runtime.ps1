#Requires -Version 7.6
#Requires -PSEdition Core
# Shared inline runtime proof; assembled entry points supply #Requires too.
$ErrorActionPreference='Stop';$global:PSModuleAutoLoadingPreference='None'
 if($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion -lt [version]'7.6' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc') -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64'){throw 'Stable x64 PowerShell Core >=7.6 required'}
 $exe=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
 if($exe -ine 'C:\Program Files\PowerShell\7\pwsh.exe' -or $PSHOME -ine 'C:\Program Files\PowerShell\7'){throw 'Exact machine PowerShell executable and PSHOME required'}
 $env:PSModulePath='C:\Program Files\PowerShell\7\Modules;C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
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
 $AiwPowerShellRuntime=[ordered]@{edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();prerelease='';architecture=[Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString();executable=$exe;psHome=$PSHOME;executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant();capabilities=$caps;compatibilitySessionCount=$compat.Count}
