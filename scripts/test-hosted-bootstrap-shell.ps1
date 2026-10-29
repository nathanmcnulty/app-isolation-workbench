#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param()

# Bounded inert local regression using a copy of the existing runtime.
# No installer, endpoint, machine runtime or VM is changed.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'powershell-runtime.ps1')
$runtime = Assert-AiwPowerShellRuntime -AllowCurrentProcessForInertTests
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$root = Join-Path $temporaryParent ('aiw-shell fixture-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    $bootstrap = Join-Path $root 'aiw-core-bootstrap'
    Copy-Item -LiteralPath $PSHOME -Destination $bootstrap -Recurse -ErrorAction Stop
    $expectedImage = Join-Path $bootstrap 'pwsh.exe'
    if ((Get-FileHash -LiteralPath $expectedImage -Algorithm SHA256).Hash.ToLowerInvariant() -cne $runtime.executableSha256) { throw 'Copied inert image differs' }
    $probeSource = @'
#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $PSHOME 'Modules'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -SkipEditionCheck -ErrorAction Stop
$PSModuleAutoLoadingPreference='None'
if ($PSVersionTable.PSEdition -cne 'Core' -or $PSVersionTable.PSVersion.PreReleaseLabel) { throw 'Stable Core required' }
@{executable=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;psHome=$PSHOME;version=$PSVersionTable.PSVersion.ToString()}|ConvertTo-Json -Compress
exit ([int]$env:AIW_SHELL_TEST_EXIT)
'@
    $template = 'C:\Windows\System32\cmd.exe /d /v:off /s /c "if exist "{0}.ps1" (exit /b 91) else (copy /b "{0}" "{0}.ps1" >nul && "{IMAGE}" -NoLogo -NoProfile -NonInteractive -File "{0}.ps1")"'
    # Match the runner's first-space parser and unknown-shell extension behavior.
    # The machine template is path-substituted only in this inert test because
    # installing at the machine location is outside the offline scope.
    $shells = @(
        $template.Replace('{IMAGE}', '%RUNNER_TEMP%\aiw-core-bootstrap\pwsh.exe'),
        $template.Replace('{IMAGE}', 'C:\Program Files\PowerShell\7\pwsh.exe').Replace('C:\Program Files\PowerShell\7\pwsh.exe', $expectedImage)
    )
    $cases = 0
    foreach ($shell in $shells) {
        foreach ($exitCode in @(0, 42, 91)) {
            $probe = Join-Path $root ('probe with spaces-' + $cases)
            [IO.File]::WriteAllText($probe, $probeSource, [Text.UTF8Encoding]::new($false))
            if ($exitCode -eq 91) { [IO.File]::WriteAllText($probe + '.ps1', 'preserve me') }
            $split = $shell.IndexOf(' ')
            $start = [Diagnostics.ProcessStartInfo]::new($shell.Substring(0, $split), $shell.Substring($split + 1).Replace('{0}', $probe))
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            $start.Environment['RUNNER_TEMP'] = $root
            $start.Environment['AIW_SHELL_TEST_EXIT'] = [string]$exitCode
            $process = [Diagnostics.Process]::Start($start)
            try {
                $stdout = $process.StandardOutput.ReadToEndAsync()
                $stderr = $process.StandardError.ReadToEndAsync()
                if (-not $process.WaitForExit(20000)) { $process.Kill($true); throw 'Hosted shell exceeded 20 seconds' }
                if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Hosted shell pipes remained open' }
                if ($process.ExitCode -ne $exitCode -or $stderr.Result) { throw "Hosted exit/diagnostics differ: $($process.ExitCode): $($stderr.Result)" }
                if ($exitCode -eq 91) {
                    if ($stdout.Result -or [IO.File]::ReadAllText($probe + '.ps1') -cne 'preserve me') { throw 'Existing shell script was executed or overwritten' }
                } else {
                    $observed = $stdout.Result | ConvertFrom-Json
                    if ($observed.executable -ine $expectedImage -or $observed.psHome -ine $bootstrap -or $observed.version -cne $runtime.version) { throw 'Hosted shell ran an unexpected runtime' }
                    if ([IO.File]::ReadAllText($probe + '.ps1') -cne $probeSource) { throw 'Hosted script bytes differ' }
                }
            } finally { $process.Dispose() }
            $cases++
        }
    }
    [pscustomobject]@{passed=$true;cases=$cases;copiedRuntimeVersion=$runtime.version;extensionlessInput=$true;spacedPaths=$true;exit42Preserved=$true;existingFilePreserved=$true;installerExecuted=$false;vmContacted=$false}|ConvertTo-Json -Compress
} finally {
    $resolved = [IO.Path]::GetFullPath($root)
    if ((Split-Path -Parent $resolved) -ine $temporaryParent -or (Split-Path -Leaf $resolved) -notmatch '^aiw-shell fixture-[0-9a-f]{32}$' -or (Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected hosted shell fixture cleanup target' }
    if (Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) { throw 'Refusing cleanup with linked children' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
