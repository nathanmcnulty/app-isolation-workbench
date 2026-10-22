# Local controlled-cmd regression only; never calls the packaged application Create().
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\..\crates\aiw-windows-platform\src\research_msix_native.cs'
Add-Type -TypeDefinition ([IO.File]::ReadAllText($source))
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class AiwExitTestHandles {
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 public static IntPtr Duplicate(IntPtr source,uint access) {
  IntPtr copy;
  if(!DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),out copy,access,false,access==0?2u:0u))throw new Win32Exception(Marshal.GetLastWin32Error());
  return copy;
 }
}
'@
$flags = [Reflection.BindingFlags]'Instance,NonPublic'
$type = [AiwSuspendedNotepad]
$infoType = $type.GetNestedType('ProcessInfo', [Reflection.BindingFlags]::NonPublic)
$constructor = $type.GetConstructor($flags, $null, [type[]]@($infoType), $null)
$resumedField = $type.GetField('resumed', $flags)
if (!$infoType -or !$constructor -or !$resumedField) { throw 'Production reflection seam differs' }
$script:checks = @()

function New-ControlledCmd([string]$Command) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $env:windir 'System32\cmd.exe'
    $info.Arguments = '/d /q /c "' + $Command + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (!$process.Start()) { $process.Dispose(); throw 'Controlled cmd did not start' }
    $null = $process.Handle
    return $process
}
function New-ProductionWrapper($Process, [bool]$Resumed = $true, [uint32]$Access = 0) {
    $copy = [AiwExitTestHandles]::Duplicate($Process.Handle, $Access)
    try {
        $info = [Activator]::CreateInstance($infoType)
        $infoType.GetField('process').SetValue($info, $copy)
        $infoType.GetField('pid').SetValue($info, [uint32]$Process.Id)
        $wrapper = $constructor.Invoke([object[]]@($info))
        $resumedField.SetValue($wrapper, $Resumed)
        $copy = [IntPtr]::Zero
        return $wrapper
    } finally { if ($copy -ne [IntPtr]::Zero) { $null = [AiwExitTestHandles]::CloseHandle($copy) } }
}
function Assert-Rejected([scriptblock]$Action, [type]$Expected, [string]$Name) {
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_.Exception }
    while ($caught -and $caught.InnerException) { $caught = $caught.InnerException }
    if (!$caught -or $caught.GetType() -ne $Expected) { throw ($Name + ': expected ' + $Expected.FullName + ', got ' + $caught) }
    $script:checks += $Name
}
function Remove-ControlledCmd($Process, $Wrapper) {
    # The .NET handle belongs to this exact test-created process generation.
    try { if ($Wrapper) { $Wrapper.Dispose() } }
    finally {
        try { if ($Process -and !$Process.HasExited) { $Process.Kill() }; if ($Process -and !$Process.WaitForExit(5000)) { throw 'Controlled cmd cleanup unconfirmed' } }
        finally { if ($Process) { $Process.Dispose() } }
    }
}

foreach ($code in @(0, 42, 259, -1)) {
    $process = $null; $wrapper = $null
    try {
        $process = New-ControlledCmd ('exit /b ' + $code)
        $wrapper = New-ProductionWrapper $process
        $actual = $wrapper.WaitForExitCode(5000)
        $expected = if ($code -eq -1) { [uint32]::MaxValue } else { [uint32]$code }
        if ($actual -isnot [uint32] -or $actual -ne $expected) { throw "Native exit differs for $code : $actual" }
        $script:checks += ('held-native-exit-' + $expected)
        if ($wrapper.WaitForExitCode(0) -ne $expected) { throw 'Signaled zero-time wait differs' }
        $script:checks += ('signaled-zero-time-wait-' + $expected)
        if ($code -eq 0) {
            $wrapper.Dispose()
            Assert-Rejected { $wrapper.WaitForExitCode(0) } ([InvalidOperationException]) 'disposed-rejected'
        }
    } finally { Remove-ControlledCmd $process $wrapper }
}
$process = $null; $wrapper = $null
try {
    $process = New-ControlledCmd 'set /p AIW_EXIT_TEST_WAIT= & exit /b 42'
    $wrapper = New-ProductionWrapper $process
    Assert-Rejected { $wrapper.WaitForExitCode(25) } ([TimeoutException]) 'running-timeout-not-success'
    if ($process.HasExited) { throw 'Timeout control unexpectedly exited' }
    Assert-Rejected { $wrapper.WaitForExitCode(900001) } ([InvalidOperationException]) 'over-bound-rejected'
    $process.StandardInput.WriteLine('release')
    $process.StandardInput.Flush()
    if ($wrapper.WaitForExitCode(5000) -ne 42) { throw 'Timeout destroyed subsequent exact exit observation' }
    $script:checks += 'same-held-process-exit-after-timeout'
} finally { Remove-ControlledCmd $process $wrapper }

$process = $null; $wrapper = $null
try {
    $process = New-ControlledCmd 'set /p AIW_EXIT_TEST_WAIT= & exit /b 0'
    $wrapper = New-ProductionWrapper $process $false
    Assert-Rejected { $wrapper.WaitForExitCode(0) } ([InvalidOperationException]) 'unresumed-rejected'
} finally { Remove-ControlledCmd $process $wrapper }

$process = $null; $wrapper = $null
try {
    $process = New-ControlledCmd 'exit /b 0'
    $wrapper = New-ProductionWrapper $process $true 0x00100000 # SYNCHRONIZE, without query rights
    Assert-Rejected { $wrapper.WaitForExitCode(5000) } ([ComponentModel.Win32Exception]) 'exit-query-access-error-propagated'
} finally { Remove-ControlledCmd $process $wrapper }

[ordered]@{ passed = $true; checks = $checks.Count; cases = $checks; powerShell = $PSVersionTable.PSVersion.ToString(); nativeSourceSha256 = (Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() } | ConvertTo-Json -Compress
