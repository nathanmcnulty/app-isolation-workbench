[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $repoRoot 'target\guest-agent-static'
$targetTriple = 'x86_64-pc-windows-msvc'
$previousTarget = $env:CARGO_TARGET_DIR

Push-Location -LiteralPath $repoRoot
try {
    $env:CARGO_TARGET_DIR = $targetRoot
    $arguments = @('rustc', '--locked', '-p', 'aiw-guest-agent', '--target', $targetTriple)
    if ($Profile -eq 'release') {
        $arguments += @('--profile', 'release')
    }
    $arguments += @('--', '-C', 'target-feature=+crt-static')
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'statically linked guest-agent build failed'
    }

    $artifact = Join-Path $targetRoot "$targetTriple\$Profile\aiw-guest-agent.exe"
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "guest-agent artifact was not produced: $artifact"
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio discovery tool is required to verify the guest-agent PE imports'
    }
    $visualStudio = & $vswhere -latest -products * -property installationPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($visualStudio)) {
        throw 'Visual Studio Build Tools could not be resolved for PE verification'
    }
    $dumpbin = Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC\Tools\MSVC') `
        -Filter dumpbin.exe -Recurse -File | Sort-Object FullName -Descending | `
        Select-Object -First 1 -ExpandProperty FullName
    if ([string]::IsNullOrWhiteSpace($dumpbin)) {
        throw 'dumpbin.exe is required to verify the guest-agent PE imports'
    }
    $headers = & $dumpbin /headers $artifact 2>&1
    $headerText = $headers -join "`n"
    if ($LASTEXITCODE -ne 0 -or $headerText -notmatch '(?m)^\s+8664 machine \(x64\)') {
        throw 'guest-agent artifact is not an x64 PE image'
    }
    $dependencies = & $dumpbin /dependents $artifact 2>&1
    $dependencyText = $dependencies -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw 'guest-agent PE dependency inspection failed'
    }
    if ($dependencyText -match '(?im)^\s+(VCRUNTIME\d*\.dll|MSVCP\d*\.dll|UCRTBASE\.dll|api-ms-win-crt-[^\s]+\.dll)\s*$') {
        throw 'guest-agent artifact still imports a dynamic Visual C++ runtime'
    }

    [ordered]@{
        schemaVersion = 'aiw.dev/guest-agent-build/v0alpha1'
        profile = $Profile
        target = $targetTriple
        artifact = $artifact
        sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        crt = 'static'
    } | ConvertTo-Json
}
finally {
    if ($null -eq $previousTarget) {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:CARGO_TARGET_DIR = $previousTarget
    }
    Pop-Location
}
