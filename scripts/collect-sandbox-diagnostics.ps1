#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetimeoffset]$StartTime,
    [datetimeoffset]$EndTime = [datetimeoffset]::UtcNow,
    [Parameter(Mandatory)][string]$OutputDirectory
)

# Read-only host observations. This script never launches/stops a worker,
# changes services, or enables event channels. Run elevated for Hyper-V logs.
$ErrorActionPreference = 'Stop'
if ($EndTime -le $StartTime -or ($EndTime - $StartTime).TotalHours -gt 24) {
    throw 'Select an increasing interval no longer than 24 hours.'
}
$root = New-Item -ItemType Directory -Path $OutputDirectory
$channels = @(
    'Microsoft-Windows-AppModel-Runtime/Admin',
    'Microsoft-Windows-Hyper-V-Compute-Admin',
    'Microsoft-Windows-Hyper-V-Compute-Operational',
    'Microsoft-Windows-Hyper-V-Worker-Admin',
    'Microsoft-Windows-Hyper-V-Worker-Operational',
    'Microsoft-Windows-Containers-Wcifs/Operational',
    'Application',
    'System'
)
$results = foreach ($channel in $channels) {
    $name = $channel.Replace('/', '_') + '.json'
    try {
        $metadata = Get-WinEvent -ListLog $channel -ErrorAction Stop
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $channel
            StartTime = $StartTime.LocalDateTime
            EndTime = $EndTime.LocalDateTime
        } -MaxEvents 1000 -ErrorAction Stop)
        $events | ForEach-Object {
            [ordered]@{ timeCreated=$_.TimeCreated.ToUniversalTime().ToString('o'); id=$_.Id;
                provider=$_.ProviderName; level=$_.LevelDisplayName; recordId=$_.RecordId;
                message=$_.Message; xml=$_.ToXml() }
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root.FullName $name)
        [ordered]@{ channel=$channel; status='captured'; count=$events.Count;
            enabled=$metadata.IsEnabled; mayBeTruncated=($events.Count -eq 1000); file=$name }
    } catch {
        [ordered]@{ channel=$channel; status= if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'noEvents' } else { 'unavailable' };
            error=$_.Exception.Message; errorId=$_.FullyQualifiedErrorId }
    }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$computeState = @{ status='unavailable'; detail='Administrator rights required for hcsdiag list.' }
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $process = $null
    try {
        $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $env:WINDIR 'System32\hcsdiag.exe'))
        $info.ArgumentList.Add('list')
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit(30000)) {
            $process.Kill()
            $computeState = @{ status='timeout' }
        } else {
            $computeState = @{ status='captured'; exitCode=$process.ExitCode;
                stdout=$stdout.GetAwaiter().GetResult(); stderr=$stderr.GetAwaiter().GetResult() }
        }
    } catch { $computeState = @{ status='unavailable'; detail=$_.Exception.Message } }
    finally { if ($process) { $process.Dispose() } }
}
[ordered]@{
    schemaVersion='aiw.dev/wsb-host-diagnostics/v0alpha1'
    startTime=$StartTime.ToUniversalTime().ToString('o')
    endTime=$EndTime.ToUniversalTime().ToString('o')
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    channels=@($results)
    computeState=$computeState
    initializationProcesses=@(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(vmmemCm|WindowsSandbox)' } |
        Select-Object Name,ProcessId,CreationDate)
    services=@(Get-Service vmcompute,HvHost,hns -ErrorAction SilentlyContinue | Select-Object Name,Status)
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root.FullName 'collection.json')
Get-Content -LiteralPath (Join-Path $root.FullName 'collection.json')
