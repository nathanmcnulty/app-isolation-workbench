#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param()

# Inert CI-selection regression. Uses workflow code with download/install stubs.
# No machine runtime, installer, network, endpoint, or VM is used.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$source = [IO.File]::ReadAllText((Join-Path $repo '.github/workflows/ci.yml'))
$blocks = @([regex]::Matches($source, '(?m)^        run: \|\r?\n((?:(?:          [^\r\n]*|)[\r\n]+)+)') | ForEach-Object {
    [regex]::Replace($_.Groups[1].Value, '(?m)^          ', '')
})
$selectors = @($blocks | Where-Object { $_.Contains('function Get-AiwCiRuntimeDisposition') } | ForEach-Object { $_.Trim() })
if ($selectors.Count -ne 3 -or @($selectors | Select-Object -Unique).Count -ne 1) { throw 'All three CI jobs must use the same runtime selection' }
$selector = $selectors[0]
foreach ($block in $blocks) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($block, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "CI inline parser errors: $($errors -join '; ')" }
    if ($block.Contains('AIW inline runtime assertion')) {
        if (-not $block.Contains('$PSVersionTable.PSVersion.Major -ne 7 -or $PSVersionTable.PSVersion.Minor -ne 6') -or
            $block.Contains('$PSVersionTable.PSVersion.ToString() -cne') -or
            -not $block.Contains('$PSVersionTable.PSVersion.PreReleaseLabel') -or
            -not $block.Contains("ProcessArchitecture.ToString() -cne 'X64'") -or
            -not $block.Contains("MainModule.FileName -ine 'C:\Program Files\PowerShell\7\pwsh.exe'") -or
            -not $block.Contains("'C:\Program Files\PowerShell\7')")) { throw 'CI operation lost its 7.6-series or identity guard' }
    }
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($selector, [ref]$tokens, [ref]$errors)
$classifier = @($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-AiwCiRuntimeDisposition'
}, $true))
if ($classifier.Count -ne 1) { throw 'Expected one CI runtime classifier' }
$classifierSource = $classifier[0].Extent.Text
. ([scriptblock]::Create($classifierSource))
$begin = $selector.IndexOf('$observed = Read-AiwCiRuntime', [StringComparison]::Ordinal)
$end = $selector.IndexOf("'C:\Program Files\PowerShell\7' | Out-File", $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'CI runtime selection boundaries missing' }
$selection = [scriptblock]::Create($selector.Substring($begin, $end - $begin))

function New-Descriptor([string]$Version = '7.6.9') {
    [pscustomobject]@{edition='Core';version=$Version;prerelease='';architecture='X64';executable='C:\Program Files\PowerShell\7\pwsh.exe';psHome='C:\Program Files\PowerShell\7'}
}
$accepted = 0
foreach ($version in @('7.6.0','7.6.5','7.6.7','7.6.9','7.6.123')) {
    if ((Get-AiwCiRuntimeDisposition (New-Descriptor $version)) -cne 'reuse') { throw "Compatible patch rejected: $version" }
    $accepted++
}
$rejected = 0
foreach ($change in @(
    @{version='7.7.0'}, @{version='8.0.0'}, @{version='7.6'}, @{version='invalid'},
    @{prerelease='preview.1'}, @{edition='Desktop'}, @{architecture='Arm64'},
    @{architecture='X86'}, @{executable='C:\Other\pwsh.exe'}, @{psHome='C:\Other'}
)) {
    $candidate = New-Descriptor
    foreach ($key in $change.Keys) { $candidate.$key = $change[$key] }
    $failed = $false
    try { Get-AiwCiRuntimeDisposition $candidate | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw "Unsafe CI runtime accepted: $($change | ConvertTo-Json -Compress)" }
    $rejected++
}
if ((Get-AiwCiRuntimeDisposition $null) -cne 'install' -or (Get-AiwCiRuntimeDisposition (New-Descriptor '7.5.4')) -cne 'install') { throw 'Missing/older selection did not choose the pinned fallback' }

function Invoke-SelectionCase([object]$Before, [object]$After, [string]$Hash = 'ec575cef9ec56fcd905de0d5eeac9cb7f81a0a65abb87bb5cd0e87fdfe2b8cc0', [int]$ExitCode = 0) {
    $state = @{reads=0;downloads=0;installs=0;error=$null}
    function Read-AiwCiRuntime { $state.reads++; if ($state.reads -eq 1) { $Before } else { $After } }
    function Invoke-WebRequest {
        param($Uri,$OutFile)
        if ($Uri -cne 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/PowerShell-7.6.7-win-x64.msi') { throw 'Unexpected fallback download' }
        $state.downloads++
    }
    function Get-FileHash { param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=$Hash} }
    function Start-Process {
        param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru)
        if ($FilePath -cne 'msiexec.exe' -or -not $Wait -or -not $PassThru -or
            @('/quiet','/norestart','/L*v','ENABLE_PSREMOTING=0','REGISTER_MANIFEST=0','ADD_PATH=1' | Where-Object { $_ -notin $ArgumentList }).Count) { throw 'Unsafe fallback installer arguments' }
        if ($ArgumentList[1] -cne ('"' + (Join-Path $env:RUNNER_TEMP 'PowerShell-7.6.7-win-x64.msi') + '"') -or
            $ArgumentList[5] -cne ('"' + (Join-Path $env:RUNNER_TEMP 'aiw-powershell-install.log') + '"')) { throw 'Installer paths are not quoted' }
        $state.installs++
        [pscustomobject]@{ExitCode=$ExitCode}
    }
    function Test-Path { param($LiteralPath) $false }
    function Write-Host { param([Parameter(ValueFromPipeline)]$Object) process {} }
    $savedTemp = $env:RUNNER_TEMP
    try {
        $env:RUNNER_TEMP = Join-Path ([IO.Path]::GetTempPath()) 'aiw inert selection'
        try { & $selection | Out-Null } catch { $state.error = $_.Exception.Message }
    } finally { $env:RUNNER_TEMP = $savedTemp }
    [pscustomobject]$state
}
$cases = @(
    @{name='reuse';before=(New-Descriptor);after=$null;downloads=0;installs=0;reads=1;error=$null},
    @{name='older';before=(New-Descriptor '7.5.4');after=(New-Descriptor '7.6.7');downloads=1;installs=1;reads=2;error=$null},
    @{name='missing after bootstrap';before=$null;after=(New-Descriptor '7.6.7');downloads=1;installs=1;reads=2;error=$null},
    @{name='reboot exit';before=$null;after=(New-Descriptor);exit=3010;downloads=1;installs=1;reads=2;error=$null},
    @{name='newer series';before=(New-Descriptor '7.7.0');after=$null;downloads=0;installs=0;reads=1;error='no automatic downgrade'},
    @{name='hash mismatch';before=$null;after=(New-Descriptor);hash=('0'*64);downloads=1;installs=0;reads=1;error='hash differs'},
    @{name='MSI failure';before=$null;after=(New-Descriptor);exit=1603;downloads=1;installs=1;reads=1;error='MSI exit code 1603'},
    @{name='failed final proof';before=$null;after=(New-Descriptor '7.5.4');downloads=1;installs=1;reads=2;error='proof did not select'}
)
foreach ($case in $cases) {
    $arguments = @{Before=$case.before;After=$case.after}
    if ($case.ContainsKey('hash')) { $arguments.Hash = $case.hash }
    if ($case.ContainsKey('exit')) { $arguments.ExitCode = $case.exit }
    $result = Invoke-SelectionCase @arguments
    if ($result.downloads -ne $case.downloads -or $result.installs -ne $case.installs -or $result.reads -ne $case.reads -or
        ($null -eq $case.error -and $null -ne $result.error) -or
        ($null -ne $case.error -and $result.error -notlike "*$($case.error)*")) { throw "CI selection case failed: $($case.name): $($result | ConvertTo-Json -Compress)" }
}
[ordered]@{passed=$true;acceptedPatches=$accepted;rejectedDescriptors=$rejected;selectionCases=$cases.Count;workflowJobs=$selectors.Count;installerExecuted=$false;networkUsed=$false;vmContacted=$false}|ConvertTo-Json -Compress
