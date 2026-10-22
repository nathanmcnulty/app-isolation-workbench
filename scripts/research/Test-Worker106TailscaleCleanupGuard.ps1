#requires -Version 7.6
# Extract the pure identity guard only; no directory deletion is executed.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Remove-Worker106TailscaleState.ps1'),[ref]$tokens,[ref]$parseErrors)
if (@($parseErrors).Count) { throw 'Cleanup script parse failed' }
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Worker106TailscaleCleanup'},$true))
if ($functions.Count -ne 1) { throw 'Unique fixed guard required' }
Invoke-Expression $functions[0].Extent.Text
$valid=[pscustomobject]@{VmUuid='7E686BEE-8C05-43C7-9603-A9562ECE224C'; UserSid='S-1-5-21-3849540285-1795134874-2442050430-1001'; Elevated=$true; ServiceCount=0; Adapters=@([pscustomobject]@{MacAddress='CC-34-21-7E-FE-59'; Status='Disconnected'})}
Assert-Worker106TailscaleCleanup $valid
$cases=@(
    {param($o) $o.VmUuid='00000000-0000-0000-0000-000000000000'},
    {param($o) $o.UserSid='S-1-5-18'},
    {param($o) $o.Elevated=$false},
    {param($o) $o.ServiceCount=1},
    {param($o) $o.Adapters=@()},
    {param($o) $o.Adapters=@($o.Adapters[0],$o.Adapters[0])},
    {param($o) $o.Adapters[0].MacAddress='00-11-22-33-44-55'},
    {param($o) $o.Adapters[0].Status='Up'}
)
foreach ($case in $cases) {
    $observed=$valid | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    & $case $observed
    $rejected=$false
    try { Assert-Worker106TailscaleCleanup $observed } catch { $rejected=$true }
    if (-not $rejected) { throw 'Unsafe cleanup guard accepted' }
}
[ordered]@{Passed=$true; Accepted=1; Rejected=$cases.Count; DeletionExecuted=$false} | ConvertTo-Json
