# Fixed guest-agent operation. Runs as SYSTEM only, offline on the cloned worker.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    if ((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c') { throw 'Wrong VM' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or -not [Environment]::Is64BitProcess) { throw '64-bit SYSTEM required' }
    $adapters = @(Get-NetAdapter -Physical)
    if ($adapters.Count -ne 1 -or $adapters[0].MacAddress -cne 'CC-34-21-7E-FE-59' -or $adapters[0].Status -ne 'Disconnected') { throw 'Disconnected worker adapter required' }
    if (@(Get-CimInstance Win32_Service -Filter "Name='Tailscale'").Count -ne 0) { throw 'Tailscale service still exists' }
    $targets = @('C:\ProgramData\Tailscale', 'C:\Users\labadmin\AppData\Local\Tailscale', 'C:\Windows\System32\config\systemprofile\AppData\Local\Tailscale')
    # Validate all existing paths before deletion; missing directories are success.
    $existing = @()
    foreach ($target in $targets) {
        if ([IO.Path]::GetFullPath($target) -cne $target) { throw 'Noncanonical path' }
        # Walk from the drive root, including ancestors of missing targets. Do not
        # traverse a junction while deciding whether a descendant exists.
        $cursor = [IO.Path]::GetPathRoot($target)
        foreach ($component in $target.Substring($cursor.Length).Split('\')) {
            $cursor = Join-Path $cursor $component
            $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
            if ($null -eq $item) {
                if (Test-Path -LiteralPath $cursor) { throw 'Cannot inspect cleanup path' }
                break
            }
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected directory or reparse point' }
        }
        if (Test-Path -LiteralPath $target) {
            # Enumerate explicitly without following any reparse directory.
            $pending = [Collections.Generic.Stack[string]]::new()
            $pending.Push($target)
            while ($pending.Count) {
                foreach ($child in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
                    if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point inside cleanup directory' }
                    if ($child.PSIsContainer) { $pending.Push($child.FullName) }
                }
            }
            $existing += $target
        }
    }
    foreach ($target in $existing) { Remove-Item -LiteralPath $target -Recurse -Force }
    $remaining = @($targets | Where-Object { Test-Path -LiteralPath $_ })
    if ($remaining.Count) { throw 'Cleanup incomplete' }
    [ordered]@{ VmUuid='7e686bee-8c05-43c7-9603-a9562ece224c'; ServicePresent=$false; ProgramDataState=$false; UserState=$false; LegacyState=$false; Removed=$existing; Network='Disconnected'; WindowsRegistrationChanged=$false } | ConvertTo-Json -Compress
    exit 0
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
