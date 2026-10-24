#Requires -Version 7.6
#Requires -PSEdition Core
# Shared runtime policy. This file never installs or selects a runtime from PATH.
function Assert-AiwRuntimeDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Descriptor)
    if ($Descriptor.edition -cne 'Core' -or $Descriptor.version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\z' -or [version]$Descriptor.version -lt [version]'7.6' -or $Descriptor.prerelease -or $Descriptor.architecture -cne 'X64') { throw 'AIW requires stable x64 PowerShell Core >=7.6 with a complete numeric version' }
}
function Assert-AiwPowerShellRuntime {
    [CmdletBinding()]
    param([switch]$AllowCurrentProcessForInertTests)
    Assert-AiwRuntimeDescriptor ([pscustomobject]@{
        edition = $PSVersionTable.PSEdition
        version = $PSVersionTable.PSVersion.ToString()
        prerelease = [string]$PSVersionTable.PSVersion.PreReleaseLabel
        architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    })
    $executable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $expected = 'C:\Program Files\PowerShell\7\pwsh.exe'
    if (-not $AllowCurrentProcessForInertTests -and $executable -ine $expected) { throw "AIW requires the approved machine runtime at $expected; setup approval is required" }
    if ($executable -ine (Join-Path $PSHOME 'pwsh.exe') -or (Get-Item -LiteralPath $executable -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'AIW executable/PSHOME identity is unexpected or linked' }
    # Native explicit imports must succeed. Disable autoload so a Desktop-only
    # module cannot silently create a WinPSCompatSession later in this process.
    foreach ($aiwNativeModule in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) { Import-Module (Join-Path $PSHOME ('Modules\'+$aiwNativeModule+'\'+$aiwNativeModule+'.psd1')) -SkipEditionCheck -ErrorAction Stop }
    $global:PSModuleAutoLoadingPreference = 'None'
    $sessions = @(Get-PSSession | Where-Object Name -eq 'WinPSCompatSession')
    if ($sessions.Count) { throw 'AIW prohibits Windows PowerShell compatibility sessions' }
    [pscustomobject][ordered]@{
        edition = $PSVersionTable.PSEdition
        version = $PSVersionTable.PSVersion.ToString()
        prerelease = ''
        architecture = 'X64'
        executable = $executable
        psHome = $PSHOME
        executableSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        capabilities = @('NativeCoreModules','ExplicitNativeModuleImport','NoImplicitCompatibility')
        compatibilitySessionCount = $sessions.Count
    }
}

function Resolve-AiwPowerShellRuntime {
    [CmdletBinding()]
    param([switch]$AllowCurrentProcessForInertTests)
    (Assert-AiwPowerShellRuntime -AllowCurrentProcessForInertTests:$AllowCurrentProcessForInertTests).executable
}
