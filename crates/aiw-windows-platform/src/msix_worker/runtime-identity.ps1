#Requires -Version 7.6
#Requires -PSEdition Core
# Closed identity comparison: object property order carries no authority.
function Assert-AiwIdentityObject($Value,[string[]]$Keys) {
 if($Value -is [Collections.IDictionary]){$names=@($Value.Keys)}
 elseif($Value -is [pscustomobject]){$names=@($Value.PSObject.Properties.Name)}
 else{throw 'Identity must be an object'}
 if($names.Count -ne $Keys.Count){throw 'Closed identity fields required'}
 foreach($name in $names){if($name -isnot [string] -or $Keys -cnotcontains $name){throw 'Unexpected identity field'}}
 foreach($name in $Keys){if($names -cnotcontains $name){throw 'Missing identity field'}}
}
function ConvertTo-AiwClosedWorkerRuntime($Value) {
 $strings=@('edition','version','prerelease','architecture','executable','psHome','executableSha256')
 Assert-AiwIdentityObject $Value ($strings+@('capabilities','compatibilitySessionCount','engine'))
 foreach($name in $strings){if($Value.$name -isnot [string]){throw 'Runtime string field required'}}
 $engineKeys=@('assemblyPath','assemblySha256','assemblyVersion','moduleVersionId')
 Assert-AiwIdentityObject $Value.engine $engineKeys
 foreach($name in $engineKeys){if($Value.engine.$name -isnot [string]){throw 'Engine string field required'}}
 $count=$Value.compatibilitySessionCount
 # PowerShell observes Int32; ConvertFrom-Json reads JSON integers as Int64.
 if(($count -isnot [int] -and $count -isnot [long]) -or $count -ne 0){throw 'Zero integer compatibility count required'}
 $required=@('Add-Type','Get-CimInstance','Get-AppxPackage','Get-AppxPackageManifest','Add-AppxPackage','Remove-AppxPackage','Get-AppxProvisionedPackage','Get-LocalUser','New-LocalUser','Disable-LocalUser','Add-LocalGroupMember','Get-LocalGroupMember','Get-AuthenticodeSignature','Get-ScheduledTask','New-PSSession')
 if($Value.capabilities -isnot [Array] -or $Value.capabilities.Rank -ne 1 -or $Value.capabilities.Count -ne $required.Count){throw 'Closed capability array required'}
 for($i=0;$i -lt $required.Count;$i++){if($Value.capabilities[$i] -isnot [string] -or $Value.capabilities[$i] -cne $required[$i]){throw 'Native capability sequence differs'}}
 $fixedHome='C:\Program Files\PowerShell\7'
 if($Value.edition -cne 'Core' -or $Value.version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$' -or [version]$Value.version -lt [version]'7.6' -or $Value.prerelease -cne '' -or $Value.architecture -cne 'X64' -or $Value.executable -ine ($fixedHome+'\pwsh.exe') -or $Value.psHome -ine $fixedHome -or $Value.executableSha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'Fixed stable direct Core worker required'}
 $engine=$Value.engine
 if($engine.assemblyPath -ine ($fixedHome+'\System.Management.Automation.dll') -or $engine.assemblySha256 -cnotmatch '^[0-9a-f]{64}$' -or $engine.assemblyVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -or ([version]$engine.assemblyVersion).Major -ne ([version]$Value.version).Major -or ([version]$engine.assemblyVersion).Minor -ne ([version]$Value.version).Minor -or $engine.moduleVersionId -cnotmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or [guid]$engine.moduleVersionId -eq [guid]::Empty){throw 'Exact loaded Core engine required'}
 $canonical=[ordered]@{}
 foreach($name in $strings){$canonical[$name]=$Value.$name}
 $canonical.capabilities=@($Value.capabilities)
 $canonical.compatibilitySessionCount=[long]$count
 $canonical.engine=[ordered]@{}
 foreach($name in $engineKeys){$canonical.engine[$name]=$engine.$name}
 ConvertTo-Json -InputObject $canonical -Compress -Depth 8
}
function Assert-AiwWorkerRuntimeIdentity($Observed,$Binding) {
 Assert-AiwIdentityObject $Binding @('host','worker','endpoint','wsman')
 if($Binding.endpoint -isnot [string] -or $Binding.endpoint -cne 'PowerShell.7.6' -or $null -eq $Binding.wsman -or ($Binding.wsman -isnot [pscustomobject] -and $Binding.wsman -isnot [Collections.IDictionary])){throw 'Approved endpoint binding required'}
 # The native agent validates the full binding before launching these scripts.
 # Retain that required host shape; compare actual worker values independently.
 $null=ConvertTo-AiwClosedWorkerRuntime $Binding.host
 if((ConvertTo-AiwClosedWorkerRuntime $Observed) -cne (ConvertTo-AiwClosedWorkerRuntime $Binding.worker)){throw 'Approved PowerShell worker identity differs'}
}
