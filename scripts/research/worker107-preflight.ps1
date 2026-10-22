#requires -Version 5.1
# Fixed read-only preparation probe; never installs, launches or removes an app.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Set-StrictMode -Version Latest
if ($args.Count -ne 0) { throw 'Worker preflight accepts no arguments' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -cne 'S-1-5-18' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) {
    throw 'Worker preflight requires LocalSystem session zero'
}
$machine = Get-CimInstance Win32_ComputerSystemProduct
if ($machine.UUID.ToLowerInvariant() -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e') {
    throw 'Fixed worker UUID differs'
}
$os = Get-CimInstance Win32_OperatingSystem
$accounts = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' |
    Sort-Object SID | Select-Object Name,SID,Disabled)
$profiles = @(Get-CimInstance Win32_UserProfile | Sort-Object SID |
    Select-Object SID,LocalPath,Loaded,Special)
$authenticationPaths = @(
    'C:\Users\labadmin\.ssh',
    'C:\Users\labadmin\.azure',
    'C:\Users\labadmin\.codex',
    'C:\ProgramData\Tailscale',
    'C:\Users\labadmin\AppData\Local\Tailscale',
    'C:\Windows\System32\config\systemprofile\AppData\Local\Tailscale',
    'C:\Users\labadmin\AppData\Local\Microsoft\Credentials',
    'C:\Users\labadmin\AppData\Roaming\Microsoft\Credentials',
    'C:\Users\labadmin\AppData\Local\Microsoft\Vault',
    'C:\Users\labadmin\AppData\Roaming\Microsoft\Vault',
    'C:\Users\labadmin\AppData\Roaming\Microsoft\Protect',
    'C:\Users\labadmin\AppData\Local\Microsoft\Edge\User Data',
    'C:\Users\labadmin\AppData\Local\Google\Chrome\User Data'
) | ForEach-Object {
    [ordered]@{ path = $_; present = [bool](Test-Path -LiteralPath $_) }
}
$packages = @(Get-AppxPackage -AllUsers -Name AIWResearch.NotepadPP |
    Select-Object PackageFullName,InstallLocation,PackageUserInformation)
$applicationProcesses = @(Get-CimInstance Win32_Process -Filter "Name='notepad++.exe'" |
    Select-Object ProcessId,SessionId,ExecutablePath)
$tailscaleServices = @(Get-CimInstance Win32_Service -Filter "Name='Tailscale'" |
    Select-Object Name,State,StartMode,PathName)
$tailscaleInstallation = @(
    foreach ($registryRoot in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )) {
        if (Test-Path -LiteralPath $registryRoot) {
            foreach ($key in Get-ChildItem -LiteralPath $registryRoot) {
                $displayName = $key.GetValue('DisplayName')
                if ($displayName -is [string] -and $displayName -like 'Tailscale*') {
                    [ordered]@{ productKey = $key.PSChildName; displayName = $displayName; version = $key.GetValue('DisplayVersion') }
                }
            }
        }
    }
)
[ordered]@{
    schemaVersion = 'aiw.dev/worker107-preflight/v1'
    observedUtc = [DateTime]::UtcNow.ToString('o')
    workerVmId = 107
    smbiosUuid = $machine.UUID.ToLowerInvariant()
    computerName = $env:COMPUTERNAME
    observerSid = $identity.User.Value
    observerSessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    os = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber }
    accounts = $accounts
    profiles = $profiles
    authenticationPathPresence = @($authenticationPaths)
    researchPackages = $packages
    applicationProcesses = $applicationProcesses
    tailscaleServices = $tailscaleServices
    tailscaleInstallation = $tailscaleInstallation
    applicationExecuted = $false
    credentialsRead = $false
    stateMutated = $false
    recoveryBoundaryVerified = $false
} | ConvertTo-Json -Depth 8
