# Fixed SYSTEM control only. Run by the paired held-process controller.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$stage='C:\AIW-Worker-Setup\msix-vm106-staging\scheduler-control-r1'
function Publish([string]$Name,$Value) {
    $temporary=Join-Path $stage ($Name+'.tmp')
    $final=Join-Path $stage ($Name+'.json')
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 8))
    $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    [IO.File]::Move($temporary,$final)
}
try {
    if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or
       [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
       (Get-Process -Id $PID).SessionId -ne 0){throw 'Wrong SYSTEM worker'}
    $process=Get-Process -Id $PID
    Publish 'worker-process' @{pid=$PID;startFileTime=$process.StartTime.ToUniversalTime().ToFileTimeUtc();image=$process.MainModule.FileName}
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath (Join-Path $stage 'controller-ack'))){
        if($timer.Elapsed.TotalSeconds -gt 30){throw 'Controller did not acquire exact process custody'}
        Start-Sleep -Milliseconds 100
    }
    . (Join-Path $stage 'control.ps1')
    Publish 'result' (Invoke-AiwMsixSchedulerLaunchControl)
    exit 0
} catch {
    Publish 'failure' @{error=$_.Exception.ToString();applicationTrialStarted=$false}
    exit 1
}
