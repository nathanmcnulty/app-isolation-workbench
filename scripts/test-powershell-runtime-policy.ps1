#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'powershell-runtime.ps1')
$observed = Assert-AiwPowerShellRuntime -AllowCurrentProcessForInertTests
Assert-AiwRuntimeDescriptor $observed
$cases = @(
    @{edition='Desktop';version='7.6.5';prerelease='';architecture='X64'},
    @{edition='Core';version='7.5.9';prerelease='';architecture='X64'},
    @{edition='Core';version='7.6';prerelease='';architecture='X64'},
    @{edition='Core';version='7.6.0';prerelease='preview.1';architecture='X64'},
    @{edition='Core';version='7.6.5';prerelease='';architecture='Arm64'}
)
foreach ($case in $cases) {
    $rejected = $false
    try { Assert-AiwRuntimeDescriptor ([pscustomobject]$case) } catch { $rejected = $true }
    if (-not $rejected) { throw 'Runtime rejection control unexpectedly passed' }
}
if ($observed.executable -ine 'C:\Program Files\PowerShell\7\pwsh.exe') {
    $rejected = $false
    try { Assert-AiwPowerShellRuntime | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unexpected runtime was accepted as the machine runtime' }
}
$repo = Split-Path -Parent $PSScriptRoot
$files = @(Get-ChildItem (Join-Path $repo 'scripts') -Recurse -File -Include '*.ps1','*.ps1.in'; Get-ChildItem (Join-Path $repo 'fixtures/control') -File -Filter '*.ps1'; Get-ChildItem (Join-Path $repo 'powershell') -Recurse -File -Include '*.ps1','*.psm1'; Get-ChildItem (Join-Path $repo 'crates') -Recurse -File -Filter '*.ps1')
foreach ($file in $files) {
    $source = [IO.File]::ReadAllText($file.FullName)
    if ($source -notmatch '(?im)^#requires -Version 7\.6\s*$' -or $source -notmatch '(?im)^#requires -PSEdition Core\s*$') { throw "Missing stable Core baseline declaration: $($file.FullName)" }
    # This rejection test contains the forbidden tokens as data, never commands.
    if ($file.Name -notin @('test-powershell-runtime-policy.ps1','test-powershell-runtime.ps1') -and $source -match '(?i)WindowsPowerShell\\v1\.0\\powershell\.exe|&\s+powershell\.exe|UseWindowsPowerShell|Import-PSSession') { throw "Legacy execution or compatibility route remains: $($file.FullName)" }
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "PowerShell parser errors: $($file.FullName): $($errors -join '; ')" }
}
$rustSources = @(Get-ChildItem (Join-Path $repo 'crates') -Recurse -File -Filter '*.rs')
foreach ($file in $rustSources) {
    $source = [IO.File]::ReadAllText($file.FullName)
    if ($source -match 'Command::new\("(?:pwsh|powershell)(?:\.exe)?"\)') { throw "PATH-selected PowerShell launch remains: $($file.FullName)" }
    if ($source -match 'WindowsPowerShell\\v1\.0\\powershell\.exe' -and $file.FullName -notlike '*\aiw-evidence\src\msix_lifecycle.rs') { throw "Legacy executable outside classified historical reader: $($file.FullName)" }
}
foreach ($workflow in Get-ChildItem (Join-Path $repo '.github/workflows') -Filter '*.yml') {
    $source = [IO.File]::ReadAllText($workflow.FullName)
    if ($source -notmatch 'Provision stable PowerShell 7\.6\.7' -or $source -notmatch 'ec575cef9ec56fcd905de0d5eeac9cb7f81a0a65abb87bb5cd0e87fdfe2b8cc0' -or $source -notmatch 'PowerShell\\7\\pwsh\.exe') { throw "Unpinned workflow runtime: $($workflow.Name)" }
    $jobSection = ($source -split '(?m)^jobs:\r?\n',2)[1]
    $jobs = [regex]::Matches($jobSection,'(?ms)^  ([a-zA-Z][a-zA-Z0-9_-]*):\r?\n(.*?)(?=^  [a-zA-Z][a-zA-Z0-9_-]*:\r?\n|\z)')
    foreach ($job in $jobs) {
        $jobSource = $job.Groups[2].Value
        $stage = $jobSource.IndexOf('Stage trusted hosted Core bootstrap away from the installation')
        $provision = $jobSource.IndexOf('Provision stable PowerShell 7.6.7')
        $firstOperation = $jobSource.IndexOf('AIW inline runtime assertion')
        if ($provision -lt 0 -or $firstOperation -lt 0 -or $provision -gt $firstOperation) { throw "Job lacks runtime provisioning before its first operation: $($workflow.Name)/$($job.Groups[1].Value)" }
        if ($stage -lt 0 -or $stage -gt $provision -or $jobSource -notmatch 'shell: ''"\$\{\{ runner.temp \}\}\\aiw-core-bootstrap\\pwsh.exe"') { throw "MSI provisioning must run from a staged copy after the original runtime exits: $($workflow.Name)/$($job.Groups[1].Value)" }
        if ([regex]::Matches($jobSource,'name: Stage trusted hosted Core bootstrap').Count -ne 1 -or [regex]::Matches($jobSource,'name: Provision stable PowerShell').Count -ne 1) { throw 'Each job must stage and provision its runtime exactly once' }
        if ($jobSource -notmatch "\`$env:PSModulePath = \[IO.Path\]::Combine\(\`$PSHOME, 'Modules'\)" -or $jobSource -notmatch 'Staged bootstrap runtime identity differs') { throw 'The copied bootstrap must isolate module loading from the machine runtime being upgraded' }
        if ($jobSource -match 'scripts/powershell-runtime.ps1') { throw 'Inline hosted assertions must not depend on checkout files' }
        if ($job.Groups[1].Value -in @('sign','sign-control') -and $jobSource -match 'uses: actions/checkout@') { throw 'Signing job must not check out repository sources' }
    }
    # Extract literal run blocks using this repository's fixed workflow indent.
    # Parse the generated PowerShell, including download-handoff here strings.
    foreach ($run in [regex]::Matches($source,'(?m)^        run: \|\r?\n((?:(?:          [^\r\n]*|)[\r\n]+)+)')) {
        $inline = [regex]::Replace($run.Groups[1].Value,'(?m)^          ','')
        $tokens=$null; $errors=$null
        [void][Management.Automation.Language.Parser]::ParseInput($inline,[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw "Workflow PowerShell parser errors: $($workflow.Name): $($errors -join '; ')" }
        $stagingOnly = $inline -match 'Copy-Item -LiteralPath \$PSHOME -Destination \$bootstrap' -and $inline -match 'Copied bootstrap image hash differs' -and $inline -notmatch 'Start-Process|scripts\\|scripts/'
        if (-not $stagingOnly -and $inline -notmatch 'PowerShell-7\.6\.7-win-x64\.msi' -and $inline -notmatch 'AIW inline runtime assertion') { throw "Workflow run block lacks runtime assertion: $($workflow.Name)" }
        if ($inline -match 'Hosted step native command failed') { throw 'Broad stale native exit checks must not decide in-process script success' }
    }
}
$unsupported = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test-control-sandbox.ps1'))
if ($unsupported -notmatch 'Unsupported path:' -or $unsupported -match "'start','--raw'") { throw 'Offline control must fail before Sandbox launch until a verified runtime bootstrap exists' }
[ordered]@{passed=$true;runtime=$observed;rejectionCases=$cases.Count;launchGraphFiles=$files.Count;offlineSandboxControl='unsupported-before-launch'} | ConvertTo-Json -Depth 5 -Compress
