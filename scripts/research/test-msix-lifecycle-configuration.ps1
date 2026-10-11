#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
[IO.Directory]::CreateDirectory($EvidenceDirectory) | Out-Null
# Extract only these project-owned helpers. Never execute the application trial.
$sourcePath = Join-Path $PSScriptRoot '../../crates/aiw-windows-platform/src/research_msix_lifecycle.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw 'Lifecycle source parse failed' }
foreach ($name in @('Hash', 'ConfigSnapshot')) {
    $functions = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true))
    if ($functions.Count -ne 1) { throw 'Unique fixed configuration helper required' }
    Invoke-Expression $functions[0].Extent.Text
}
function Assert-Rejected([scriptblock]$Action, [string]$Expected) {
    $rejected = $false
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -notlike "*$Expected*") { throw }; $rejected = $true }
    if (!$rejected) { throw "Expected rejection: $Expected" }
}
function Write-Fixture([string]$Root, [int]$Count, [long]$Size) {
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    for ($index = 0; $index -lt $Count; $index++) {
        $stream = [IO.File]::Open((Join-Path $Root "$index.xml"), [IO.FileMode]::CreateNew)
        try { $stream.SetLength($Size) } finally { $stream.Dispose() }
    }
}
$oldRoaming = $env:APPDATA; $oldLocal = $env:LOCALAPPDATA
$passed = @()
try {
    foreach ($case in @('empty', 'one', 'count', 'total', 'file')) {
        $env:APPDATA = Join-Path $EvidenceDirectory "$case/roaming"
        $env:LOCALAPPDATA = Join-Path $EvidenceDirectory "$case/local"
        $root = Join-Path $env:APPDATA 'Notepad++'
        switch ($case) {
            empty { if (@(ConfigSnapshot '').Count -ne 0) { throw 'Empty configuration differs' } }
            one {
                Write-Fixture $root 1 32
                $snapshot = @(ConfigSnapshot '')
                if ($snapshot.Count -ne 1 -or $snapshot[0].sizeBytes -ne 32 -or $snapshot[0].sha256 -cne (Get-FileHash (Join-Path $root '0.xml')).Hash.ToLowerInvariant()) { throw 'Configuration bytes differ' }
            }
            count { Write-Fixture $root 17 0; Assert-Rejected { ConfigSnapshot '' } 'Combined configuration snapshot bound exceeded' }
            total { Write-Fixture $root 5 4MB; Assert-Rejected { ConfigSnapshot '' } 'Combined configuration snapshot bound exceeded' }
            file { Write-Fixture $root 1 (4MB + 1); Assert-Rejected { ConfigSnapshot '' } 'Configuration file refused' }
        }
        $passed += $case
    }
} finally { $env:APPDATA = $oldRoaming; $env:LOCALAPPDATA = $oldLocal }
[pscustomobject]@{ passed = $true; powerShellVersion = $PSVersionTable.PSVersion.ToString(); cases = $passed; applicationTrialExecuted = $false; evidence = $EvidenceDirectory } | ConvertTo-Json -Compress
