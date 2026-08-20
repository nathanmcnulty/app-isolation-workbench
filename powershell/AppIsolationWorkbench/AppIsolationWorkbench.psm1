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

function Get-AiwHostProbe {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string] $CliPath
    )

    Invoke-Aiw -CliPath $CliPath -ArgumentList @('probe', 'host')
}

Export-ModuleMember -Function @(
    'Get-AiwHostProbe',
    'Invoke-Aiw',
    'Test-AiwEvidence',
    'Test-AiwProject'
)
