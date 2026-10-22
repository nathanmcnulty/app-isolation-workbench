#requires -Version 7.6
# Removes only observed copied Tailscale directories, offline on VM 106.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Worker106TailscaleCleanup([object]$Observed) {
    if ($Observed.VmUuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM; stop here' }
    if ($Observed.UserSid -cne 'S-1-5-21-3849540285-1795134874-2442050430-1001' -or -not $Observed.Elevated) { throw 'Expected elevated worker labadmin required' }
    if ($Observed.ServiceCount -ne 0) { throw 'Tailscale service still exists; stop here' }
    if ($Observed.Adapters.Count -ne 1 -or $Observed.Adapters[0].MacAddress -cne 'CC-34-21-7E-FE-59' -or $Observed.Adapters[0].Status -cne 'Disconnected') { throw 'Exact disconnected physical adapter required' }
}

$vm = Get-CimInstance Win32_ComputerSystemProduct
if ($vm.UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM; stop here' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$observed = [pscustomobject]@{
    VmUuid = $vm.UUID; UserSid = $identity.User.Value
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    ServiceCount = @(Get-CimInstance Win32_Service -Filter "Name='Tailscale'").Count
    Adapters = @(Get-NetAdapter -Physical | ForEach-Object { [pscustomobject]@{ MacAddress=$_.MacAddress; Status=$_.Status.ToString() } })
}
Assert-Worker106TailscaleCleanup $observed
$targets = @('C:\ProgramData\Tailscale', 'C:\Users\labadmin\AppData\Local\Tailscale')
# Validate every absolute path, ancestor and descendant before deleting either.
foreach ($target in $targets) {
    if ([IO.Path]::GetFullPath($target) -cne $target) { throw 'Noncanonical cleanup path' }
    $item = Get-Item -LiteralPath $target -Force
    if (-not $item.PSIsContainer -or $item.FullName -ine $target) { throw 'Unexpected cleanup directory' }
    $ancestor = $item
    while ($null -ne $ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point in cleanup path; stop here' }
        $ancestor = $ancestor.Parent
    }
    $links = @(Get-ChildItem -LiteralPath $target -Force -Recurse -Attributes ReparsePoint)
    if ($links.Count -ne 0) { throw 'Reparse point inside cleanup directory; stop here' }
}
foreach ($target in $targets) {
    Remove-Item -LiteralPath $target -Recurse -Force
    if (Test-Path -LiteralPath $target) { throw "Cleanup incomplete: $target" }
}
[ordered]@{ VmUuid=$vm.UUID; Removed=$targets; TailscaleServicePresent=$false; Network='physical adapter remains disconnected'; CloudLogoutOrDeregistration='not performed' } | ConvertTo-Json -Depth 3
