Set-StrictMode -Version Latest

function Resolve-AiwCli {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $CliPath
    )

    if ($CliPath) {
        $resolved = Resolve-Path -LiteralPath $CliPath -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
            throw "AIW CLI path is not a file: $resolved"
        }
        return $resolved.Path
    }

    $command = Get-Command -Name 'aiw' -CommandType Application -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'The aiw executable was not found. Supply -CliPath or add it to PATH.'
    }
    return $command.Source
}

function Invoke-Aiw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $ArgumentList,

        [Parameter()]
        [string] $CliPath,

        [Parameter()]
        [switch] $Raw
    )

    $executable = Resolve-AiwCli -CliPath $CliPath
    $output = & $executable @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "AIW CLI failed with exit code $LASTEXITCODE."
    }
    if ($Raw) {
        return $output
    }
    return $output | ConvertFrom-Json -Depth 100
}

function Test-AiwProject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [string] $CliPath
    )

    $projectPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @('project', 'validate', '--path', $projectPath)
}

function Test-AiwEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter()]
        [string] $CliPath
    )

    $evidencePath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @('evidence', 'verify', '--log', $evidencePath)
}

function Get-AiwAssessmentBundleManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $RootPath,

        [Parameter(Mandatory)]
        [string] $SpecPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
    $resolvedSpec = (Resolve-Path -LiteralPath $SpecPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'bundle', 'build', '--root', $resolvedRoot, '--spec', $resolvedSpec
    )
}

function Test-AiwAssessmentBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $RootPath,

        [Parameter(Mandatory)]
        [string] $ManifestPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
    $resolvedManifest = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'bundle', 'verify', '--root', $resolvedRoot, '--manifest', $resolvedManifest
    )
}

function Test-AiwCanaryObservationSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlanPath,

        [Parameter(Mandatory)]
        [string] $ObservationsPath,

        [Parameter(Mandatory)]
        [string] $EvidenceLogPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedPlan = (Resolve-Path -LiteralPath $PlanPath -ErrorAction Stop).Path
    $resolvedObservations = (Resolve-Path -LiteralPath $ObservationsPath -ErrorAction Stop).Path
    $resolvedEvidence = (Resolve-Path -LiteralPath $EvidenceLogPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'canary', 'evaluate',
        '--plan', $resolvedPlan,
        '--observations', $resolvedObservations,
        '--evidence-log', $resolvedEvidence
    )
}

function Test-AiwAnalystReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ReportPath,

        [Parameter(Mandatory)]
        [string] $EvidencePath,

        [Parameter(Mandatory)]
        [string] $ModelPackPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedReport = (Resolve-Path -LiteralPath $ReportPath -ErrorAction Stop).Path
    $resolvedEvidence = (Resolve-Path -LiteralPath $EvidencePath -ErrorAction Stop).Path
    $resolvedModelPack = (Resolve-Path -LiteralPath $ModelPackPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'analyst', 'validate',
        '--report', $resolvedReport,
        '--evidence-log', $resolvedEvidence,
        '--model-pack', $resolvedModelPack
    )
}

function Get-AiwHostProbe {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $CliPath
    )

    Invoke-Aiw -CliPath $CliPath -ArgumentList @('probe', 'host')
}

function Get-AiwTokenEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $CliPath
    )

    Invoke-Aiw -CliPath $CliPath -ArgumentList @('probe', 'token')
}

function ConvertTo-AiwWindowsSandboxConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlanPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedPlan = (Resolve-Path -LiteralPath $PlanPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @('provider', 'wsb', '--plan', $resolvedPlan)
}

function Get-AiwWindowsSandboxCliLifecyclePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlanPath,

        [Parameter(Mandatory)]
        [string] $BinaryPath,

        [Parameter(Mandatory)]
        [guid] $SandboxId,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedPlan = (Resolve-Path -LiteralPath $PlanPath -ErrorAction Stop).Path
    $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'provider',
        'wsb-cli',
        '--plan', $resolvedPlan,
        '--binary', $resolvedBinary,
        '--sandbox-id', $SandboxId.ToString('D')
    )
}

function Test-AiwWindowsSandboxCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OutputRoot,

        [Parameter(Mandatory)]
        [string] $ExpectationPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedOutput = (Resolve-Path -LiteralPath $OutputRoot -ErrorAction Stop).Path
    $resolvedExpectation = (Resolve-Path -LiteralPath $ExpectationPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @(
        'provider',
        'wsb-receipt',
        '--output-root', $resolvedOutput,
        '--expectation', $resolvedExpectation
    )
}

function Get-AiwMxcInvocationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $PlanPath,

        [Parameter()]
        [string] $CliPath
    )

    $resolvedPlan = (Resolve-Path -LiteralPath $PlanPath -ErrorAction Stop).Path
    Invoke-Aiw -CliPath $CliPath -ArgumentList @('provider', 'mxc', '--plan', $resolvedPlan)
}

function Get-AiwMxcCapabilityProbePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $BinaryPath,

        [Parameter()]
        [string] $CliPath
    )

    Invoke-Aiw -CliPath $CliPath -ArgumentList @('provider', 'mxc-probe', '--binary', $BinaryPath)
}

Export-ModuleMember -Function @(
    'ConvertTo-AiwWindowsSandboxConfig',
    'Get-AiwHostProbe',
    'Get-AiwMxcCapabilityProbePlan',
    'Get-AiwMxcInvocationPlan',
    'Get-AiwTokenEvidence',
    'Get-AiwWindowsSandboxCliLifecyclePlan',
    'Invoke-Aiw',
    'Get-AiwAssessmentBundleManifest',
    'Test-AiwAssessmentBundle',
    'Test-AiwCanaryObservationSet',
    'Test-AiwAnalystReport',
    'Test-AiwEvidence',
    'Test-AiwProject',
    'Test-AiwWindowsSandboxCompletion'
)
