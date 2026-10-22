#requires -Version 7.6
# Extract only the pure guard; never execute the worker setup body.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$source = Join-Path $PSScriptRoot 'Initialize-Worker106.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if (@($parseErrors).Count) { throw 'Worker setup parse failed' }
$functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-Worker106Setup' }, $true))
if ($functions.Count -ne 1) { throw 'Unique fixed guard required' }
Invoke-Expression $functions[0].Extent.Text
$valid = [pscustomobject]@{
    VmUuid = '7E686BEE-8C05-43C7-9603-A9562ECE224C'; Computer = 'PASSKEYS'
    UserSid = 'S-1-5-21-3849540285-1795134874-2442050430-1001'
    Elevated = $true; Is64Bit = $true; DomainJoined = $false
    AzureAdJoined = 'NO'; EnterpriseJoined = 'NO'
    Adapters = @([pscustomobject]@{ MacAddress = 'CC-34-21-7E-FE-59'; Status = 'Disconnected' })
    AdminExists = $false; StageExists = $false
}
Assert-Worker106Setup $valid
$cases = @(
    @{Name='controllerUuid'; Change={param($o) $o.VmUuid='00000000-0000-0000-0000-000000000000'}},
    @{Name='wrongComputer'; Change={param($o) $o.Computer='OTHER'}},
    @{Name='wrongOperator'; Change={param($o) $o.UserSid='S-1-5-18'}},
    @{Name='notElevated'; Change={param($o) $o.Elevated=$false}},
    @{Name='wrongArchitecture'; Change={param($o) $o.Is64Bit=$false}},
    @{Name='domainJoined'; Change={param($o) $o.DomainJoined=$true}},
    @{Name='entraJoined'; Change={param($o) $o.AzureAdJoined='YES'}},
    @{Name='enterpriseJoined'; Change={param($o) $o.EnterpriseJoined='YES'}},
    @{Name='noPhysicalAdapter'; Change={param($o) $o.Adapters=@()}},
    @{Name='additionalAdapter'; Change={param($o) $o.Adapters=@($o.Adapters[0],$o.Adapters[0])}},
    @{Name='wrongMac'; Change={param($o) $o.Adapters[0].MacAddress='00-11-22-33-44-55'}},
    @{Name='networkConnected'; Change={param($o) $o.Adapters[0].Status='Up'}},
    @{Name='existingAdministrator'; Change={param($o) $o.AdminExists=$true}},
    @{Name='existingEvidence'; Change={param($o) $o.StageExists=$true}}
)
foreach ($case in $cases) {
    $observed = $valid | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    & $case.Change $observed
    $rejected = $false
    try { Assert-Worker106Setup $observed } catch { $rejected = $true }
    if (-not $rejected) { throw "Unsafe preflight accepted: $($case.Name)" }
}
[ordered]@{ Passed=$true; Accepted=1; Rejected=$cases.Count; WorkerMutationExecuted=$false } | ConvertTo-Json
