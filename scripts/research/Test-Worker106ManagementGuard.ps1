# Pure identity tests; no firewall, service, account or certificate mutation.
$ErrorActionPreference='Stop'
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot Enable-Worker106Management.ps1),[ref]$t,[ref]$e)
if($e.Count){throw 'Management parse failed'}
$guard=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-ManagementIdentity'},$true))
if($guard.Count -ne 1){throw 'Unique guard required'}
Invoke-Expression $guard[0].Extent.Text
$valid=[pscustomobject]@{Uuid='7e686bee-8c05-43c7-9603-a9562ece224c';Computer='PASSKEYS-WORKER';Sid='S-1-5-18';Is64Bit=$true;Adapters=@([pscustomobject]@{MacAddress='CC-34-21-7E-FE-59'});DomainJoined=$false;TailscalePresent=$false;AdminSid='S-1-5-21-3849540285-1795134874-2442050430-1006';AdminEnabled=$true}
Assert-ManagementIdentity $valid
$cases=@({param($o)$o.Uuid='wrong'},{param($o)$o.Computer='PASSKEYS'},{param($o)$o.Sid='S-1-5-21-1001'},{param($o)$o.Is64Bit=$false},{param($o)$o.Adapters=@()},{param($o)$o.Adapters=@($o.Adapters[0],$o.Adapters[0])},{param($o)$o.Adapters[0].MacAddress='00-00-00-00-00-00'},{param($o)$o.DomainJoined=$true},{param($o)$o.TailscalePresent=$true},{param($o)$o.AdminSid='S-1-5-18'},{param($o)$o.AdminEnabled=$false})
foreach($case in $cases){$o=$valid|ConvertTo-Json -Depth 5|ConvertFrom-Json;&$case $o;$reject=$false;try{Assert-ManagementIdentity $o}catch{$reject=$true};if(-not $reject){throw 'Unsafe management identity accepted'}}
[ordered]@{Accepted=1;Rejected=$cases.Count;WorkerOrControllerMutations=$false}|ConvertTo-Json
