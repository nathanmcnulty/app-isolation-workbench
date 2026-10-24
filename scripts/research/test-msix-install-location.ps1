#Requires -Version 7.6
#Requires -PSEdition Core
# Extract only the captured-path assignment, guard and cleanup Test-Path expression.
# No application registration, installation or lifecycle body is executed.
$ErrorActionPreference = 'Stop'
if ([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSVersionTable.PSVersion.ToString() -match '-' -or ($PSVersionTable.ContainsKey('GitCommitId') -and $PSVersionTable.GitCommitId -match 'preview|rc')) { throw 'Stable x64 PowerShell Core >=7.6 required; prerelease runtime refused' }
$PSModuleAutoLoadingPreference = 'None'
foreach ($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')) { Import-Module $module -SkipEditionCheck -ErrorAction Stop }
if (@(Get-PSSession -ErrorAction SilentlyContinue | Where-Object Name -eq 'WinPSCompatSession').Count) { throw 'Windows compatibility session forbidden' }

Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../../crates/aiw-windows-platform/src/research_msix_lifecycle.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw 'Lifecycle source parse failed' }
$assignments = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and
    $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
    $node.Left.VariablePath.UserPath -ceq 'installedLocation'
}, $true))
$guards = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
    $node.Extent.Text -match '\Aif\s*\(\[string\]::IsNullOrWhiteSpace\(\$installedLocation\)\)'
}, $true))
$presence = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Test-Path' -and
    @($node.CommandElements | Where-Object {
        $_ -is [Management.Automation.Language.VariableExpressionAst] -and
        $_.VariablePath.UserPath -ceq 'installedLocation'
    }).Count -eq 1
}, $true))
if ($assignments.Count -ne 1 -or $guards.Count -ne 1 -or $presence.Count -ne 1) { throw 'Expected unique production captured-path operations' }
$captureBlock = [scriptblock]::Create($assignments[0].Extent.Text)
$guardBlock = [scriptblock]::Create($guards[0].Extent.Text)
$presenceBlock = [scriptblock]::Create($presence[0].Extent.Text)
function Get-CapturedPath($Installed) {
    $installedLocation = $null
    . $captureBlock
    . $guardBlock
    return $installedLocation
}
function Test-CapturedPath([string]$InstalledLocation) { . $presenceBlock }
$cases = @()
foreach ($value in @($null, '', '   ')) {
    $rejected = $false
    try { Get-CapturedPath ([pscustomobject]@{ InstallLocation = $value }) | Out-Null }
    catch { if ($_.Exception.Message -cne 'Installed path absent') { throw }; $rejected = $true }
    if (!$rejected) { throw 'Missing or whitespace installed path was accepted' }
}
$cases += 'null-empty-whitespace-rejected'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = [IO.Path]::GetFullPath((Join-Path $tempRoot ('aiw-msix-install-location-' + [Guid]::NewGuid().ToString('N'))))
if ([IO.Path]::GetDirectoryName($root) -ine $tempRoot.TrimEnd('\')) { throw 'Temporary fixture escaped its parent' }
$packagePath = Join-Path $root 'installed-package'
try {
    [IO.Directory]::CreateDirectory($packagePath) | Out-Null
    $installed = [pscustomobject]@{ InstallLocation = $packagePath }
    $captured = Get-CapturedPath $installed
    $installed.InstallLocation = $null
    if ($null -ne $installed.InstallLocation -or $captured -isnot [string] -or $captured -cne $packagePath) { throw 'Source invalidation changed captured path' }
    $cases += 'captured-string-survives-cleared-source'
    if (!(Test-CapturedPath $captured)) { throw 'Existing captured installation path reported absent' }
    $cases += 'present-path-readback'
    [IO.Directory]::Delete($packagePath)
    if (Test-CapturedPath $captured) { throw 'Removed captured installation path reported present' }
    $cases += 'absent-path-readback'
} finally {
    # Both fixture directories are empty; deletion never recurses or follows children.
    if ([IO.Directory]::Exists($packagePath)) { [IO.Directory]::Delete($packagePath) }
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root) }
}
[ordered]@{ passed = $true; powerShell = $PSVersionTable.PSVersion.ToString(); cases = $cases; applicationTrialExecuted = $false } | ConvertTo-Json -Compress
