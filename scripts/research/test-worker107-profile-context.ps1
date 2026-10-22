#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot 'worker107-reset-profile.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$function = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Assert-AiwWorker107ProfileContext'
}, $true)
if ($null -eq $function) { throw 'Profile context guard not found' }
# Load only the pure guard, never the reset script's operational body.
. ([scriptblock]::Create($function.Extent.Text))
$native = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Value.Contains('public static class AiwWorker107Userenv')
}, $true)
Add-Type -TypeDefinition $native.Value
$sid = 'S-1-5-21-3556347314-2314855617-1438300668-1001'
function New-Context {
    @{
        ActorSid = 'S-1-5-18'; SessionId = 0; Impersonating = $false
        Uuid = 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'
        Accounts = @([pscustomobject]@{ Name = 'labadmin'; SID = $sid; Disabled = $false })
        Profiles = @([pscustomobject]@{ SID = $sid; LocalPath = 'C:\Users\labadmin'; Loaded = $false; Special = $false })
    }
}
$context = New-Context
Assert-AiwWorker107ProfileContext @context
$cases = @('ordinaryActor', 'interactiveActor', 'impersonation', 'developmentVm',
    'otherAccount', 'renamedAccount', 'disabledAccount', 'loadedProfile',
    'specialProfile', 'systemProfilePath', 'duplicateProfile', 'aliasedPath',
    'missingProfile', 'stringLoaded', 'stringSpecial', 'stringDisabled')
foreach ($case in $cases) {
    $context = New-Context
    switch ($case) {
        ordinaryActor { $context.ActorSid = $sid }
        interactiveActor { $context.SessionId = 1 }
        impersonation { $context.Impersonating = $true }
        developmentVm { $context.Uuid = '652a575b-a462-418e-95bb-360b28516925' }
        otherAccount { $context.Accounts[0].SID = 'S-1-5-18' }
        renamedAccount { $context.Accounts[0].Name = 'Administrator' }
        disabledAccount { $context.Accounts[0].Disabled = $true }
        loadedProfile { $context.Profiles[0].Loaded = $true }
        specialProfile { $context.Profiles[0].Special = $true }
        systemProfilePath { $context.Profiles[0].LocalPath = 'C:\Windows\System32\config\systemprofile' }
        duplicateProfile { $context.Profiles += $context.Profiles[0] }
        aliasedPath { $context.Profiles += [pscustomobject]@{ SID = 'S-1-5-18'; LocalPath = 'C:\Users\labadmin'; Loaded = $true; Special = $true } }
        missingProfile { $context.Profiles = @() }
        stringLoaded { $context.Profiles[0].Loaded = 'false' }
        stringSpecial { $context.Profiles[0].Special = 'false' }
        stringDisabled { $context.Accounts[0].Disabled = 'false' }
    }
    $rejected = $false
    try { Assert-AiwWorker107ProfileContext @context } catch { $rejected = $true }
    if (!$rejected) { throw "Profile guard accepted invalid context: $case" }
}
[ordered]@{
    passed = $true; positiveCases = 1; negativeCases = $cases.Count
    powerShellVersion = $PSVersionTable.PSVersion.ToString()
    nativeSourceCompiled = $true; nativeProfileApisInvoked = $false
} | ConvertTo-Json
