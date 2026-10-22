# Fault-inject only the actual controller's finally block; never dispatch a task.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-Worker106SchedulerControl.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$outer=$ast.Find({param($node) $node -is [Management.Automation.Language.TryStatementAst] -and $node.Finally -and $node.Finally.Extent.Text.Contains('Task cleanup is independent')},$true)
if(!$outer){throw 'Controller cleanup block absent'}
$text=$outer.Finally.Extent.Text
$cleanup=[scriptblock]::Create($text.Substring(1,$text.Length-2))
foreach($case in @('unverifiedPid','killFails','bothFail')){
    $state=@{taskPresent=$true;stopped=$false;removed=$false;killCalled=$false;disposed=$false}
    $process=[pscustomobject]@{HasExited=$false}
    $process|Add-Member ScriptMethod Kill {$state.killCalled=$true;throw 'simulated exact-process failure'}
    $process|Add-Member ScriptMethod Dispose {$state.disposed=$true}
    $verifiedProcess=$case -ne 'unverifiedPid'
    $registered=$true;$heldFiles=@();$cleanupErrors=@();$workerExited=$false;$taskName='mock-only'
    function Stop-ScheduledTask {param($TaskName) $state.stopped=$true;if($case -eq 'bothFail'){throw 'simulated task failure'}}
    function Get-ScheduledTask {param($TaskName,$ErrorAction) if($state.taskPresent){[pscustomobject]@{State='Ready'}}}
    function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm) $state.removed=$true;$state.taskPresent=$false}
    . $cleanup
    if(!$state.stopped -or !$state.disposed){throw "Independent cleanup skipped: $case"}
    if($case -eq 'unverifiedPid' -and ($state.killCalled -or $cleanupErrors.Count)){throw 'Unverified PID was terminated'}
    if($case -eq 'killFails' -and (!$state.removed -or $cleanupErrors.Count -ne 1)){throw 'Task cleanup skipped after Kill failure'}
    if($case -eq 'bothFail' -and $cleanupErrors.Count -ne 2){throw 'Cleanup failures were not both retained'}
}
[pscustomobject]@{passed=$true;cases=@('unverifiedPid','killFails','bothFail');liveTaskDispatched=$false}|ConvertTo-Json -Compress
