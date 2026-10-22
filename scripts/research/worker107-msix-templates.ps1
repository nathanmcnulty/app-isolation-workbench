# Pure conversion of reviewed fixed Scheduler control templates to the same
# custody/cleanup path for the full native lifecycle. Never executes a template.
function ConvertTo-LifecycleWorker([string]$Source) {
    $source = $Source.Replace("'vm-launch-control'", "'vm-controller'").Replace("command='vm-launch-control'", "command='vm-controller'")
    $source = $source.Replace('WaitForExit(120000)', 'WaitForExit(1260000)').Replace('deadlineSeconds=120', 'deadlineSeconds=1260')
    $source = $source.Replace("'launch-control-result.json'", "'result.json'").Replace('\launch-control-result.json','\result.json')
    $begin = $source.IndexOf("`$nativeRoot='C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle'")
    $end = $source.IndexOf(" Publish 'observation.json'", $begin)
    if ($begin -lt 0 -or $end -le $begin) { throw 'Fixed worker control block not found' }
    $block = @'
$nativeRoot='C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle'
$result=Get-Content -LiteralPath ($nativeRoot+'\result.json') -Raw|ConvertFrom-Json
$job=Get-Content -LiteralPath ($nativeRoot+'\controller-job.json') -Raw|ConvertFrom-Json
$bound=Get-Content -LiteralPath 'C:\AIW-Msix-Lifecycle-Preparation.json' -Raw|ConvertFrom-Json
if($native.runNonce -cne $nonce -or $bound.runNonce -cne $nonce -or $job.processId -ne $native.pid -or $job.sessionId -ne 0 -or $job.inAnyJob -or $result.passed -isnot [bool] -or !$result.passed -or $result.jobEmpty -isnot [bool] -or !$result.jobEmpty){throw 'Native lifecycle result or custody binding differs'}
Publish 'native-lifecycle.json' @{nonce=$nonce;wrapper=$native;result=$result;controllerJob=$job;applicationTrialMode=$true}

'@
    $source = $source.Substring(0,$begin) + $block + $source.Substring($end)
    $source.Replace('applicationLaunchAttempted=$false','applicationTrialMode=$true')
}
function ConvertTo-LifecycleController([string]$Source) {
    $source = $Source.Replace('PT260S','PT1500S').Replace('FromSeconds(260)','FromSeconds(1500)').Replace('AddSeconds(210)','AddSeconds(1440)')
    $source = $source.Replace("'native-control.json'", "'native-lifecycle.json'")
    $source = $source.Replace('$result.applicationLaunchAttempted -or ', '').Replace('$native.applicationLaunchAttempted -or ', '')
    $source = $source.Replace('-or $native.result.exitCode -ne 42 ', '')
    $source = $source.Replace('nativePrimaryControlOnly=$true','nativePrimaryControlOnly=$false')
    $source = $source.Replace('applicationLaunchAttempted=$false','applicationTrialMode=$true')
    $source.Replace('nativeControl=$native','nativeLifecycle=$native')
}
