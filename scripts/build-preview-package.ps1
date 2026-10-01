[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,
    [ValidateSet('NotepadPlusPlus', 'NotepadPlusPlusInteractive', 'BambuStudioExport')]
    [string]$Product = 'NotepadPlusPlus',
    [string]$GuestAgent,
    [string]$GuestAgentSha256,
    [string]$LaunchProfile,
    [string]$LaunchProfileSha256,
    [string]$ArchivePath
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$isBambu = $Product -eq 'BambuStudioExport'
$isInteractive = $Product -eq 'NotepadPlusPlusInteractive'
$productDirectory = if ($isBambu) { 'bambu-studio' } elseif ($isInteractive) { 'notepad-plus-plus-interactive' } else { 'notepad-plus-plus' }
$productId = if ($isBambu) { 'bambu-studio-export' } elseif ($isInteractive) { 'notepad-plus-plus-interactive' } else { 'notepad-plus-plus-local-settings' }
$scenarioIdExpected = if ($isBambu) { 'local-file-export' } else { 'install-launch-close' }
$projectFile = if ($isBambu) { 'project.json' } else { 'project.yaml' }
$productRoot = Join-Path $repoRoot "crates\aiw-cli\product\$productDirectory"
$buildTarget = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
    Join-Path $repoRoot 'target'
} else {
    [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
}
$cliSource = Join-Path $buildTarget 'release\aiw.exe'
$projectSource = Join-Path $productRoot $projectFile
$manifestSource = Join-Path $productRoot 'manifest.json'
$readmeFile = if ($isBambu) { 'packaging\preview\README-bambu.txt' } elseif ($isInteractive) { 'packaging\preview\README-interactive.txt' } else { 'packaging\preview\README.txt' }
$readmeTemplate = Join-Path $repoRoot $readmeFile
$verifierSource = Join-Path $PSScriptRoot 'verify-preview-package.ps1'
$licenseSource = Join-Path $repoRoot 'LICENSE'
$output = [IO.Path]::GetFullPath($OutputDirectory)
$packagedProductRoot = Join-Path $output "product\$productDirectory"
$targetTriple = 'x86_64-pc-windows-msvc'

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Assert-LowerSha256([string]$Value, [string]$Name) {
    if ($Value -notmatch '^[0-9a-f]{64}$') { throw "$Name must be a lowercase SHA-256" }
}

function Assert-SourceUnchanged([string]$ExpectedRevision) {
    $currentRevision = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $currentRevision -cne $ExpectedRevision) {
        throw 'Source revision changed during clean-host archive assembly'
    }
    $currentStatus = & git -C $repoRoot status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $currentStatus) {
        throw 'Source tree changed during clean-host archive assembly'
    }
}

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-Dumpbin {
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
    $dumpbin
}

function Assert-StaticX64Pe([string]$Path, [string]$ArtifactName) {
    $dumpbin = Get-Dumpbin
    $headers = & $dumpbin /headers $Path 2>&1
    if ($LASTEXITCODE -ne 0 -or ($headers -join "`n") -notmatch '(?m)^\s+8664 machine \(x64\)') {
        throw "$ArtifactName is not an x64 PE image"
    }
    $dependencies = & $dumpbin /dependents $Path 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$ArtifactName PE dependency inspection failed" }
    if (($dependencies -join "`n") -match '(?im)^\s+((?:VCRUNTIME|MSVCP|MSVCR)[^\s]*\.dll|UCRTBASE\.dll|api-ms-win-crt-[^\s]+\.dll)\s*$') {
        throw "$ArtifactName still imports a dynamic Visual C++ runtime"
    }
}

if (Test-Path -LiteralPath $output) { throw "Output directory already exists; choose a new path: $output" }
if (-not (Test-Path -LiteralPath $productRoot -PathType Container)) { throw "Required product asset directory is missing: $productRoot" }
foreach ($path in @($projectSource, $manifestSource, $readmeTemplate, $verifierSource, $licenseSource)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required product asset is missing: $path" }
}
$archive = if ([string]::IsNullOrWhiteSpace($ArchivePath)) { $null } else { [IO.Path]::GetFullPath($ArchivePath) }
if ($archive) {
    if (-not $GuestAgent -or (-not $isBambu -and -not $isInteractive -and -not $LaunchProfile)) {
        throw 'Clean-host archive assembly requires an independently retained guest agent; the Notepad++ assessment also requires a validated launch profile'
    }
    if (Test-Path -LiteralPath $archive) { throw "Archive already exists; choose a new path: $archive" }
    if (Test-Path -LiteralPath "$archive.json") { throw "Distribution manifest already exists: $archive.json" }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $archive) -PathType Container)) {
        throw 'Archive parent directory must already exist'
    }
    $sourceStatus = & git -C $repoRoot status --porcelain=v1 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $sourceStatus) {
        throw 'Clean-host archive assembly requires a clean source checkout'
    }
}

Push-Location -LiteralPath $repoRoot
try {
    $sourceRevision = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceRevision -notmatch '^[0-9a-f]{40}$') {
        throw 'Source revision could not be resolved'
    }
    $sourceTreeClean = -not [bool](& git status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw 'Source tree state could not be resolved' }
    $metadata = & cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cargo package metadata could not be resolved' }
    $packageVersion = [string]($metadata.packages | Where-Object name -eq 'aiw-cli' | Select-Object -First 1 -ExpandProperty version)
    if ([string]::IsNullOrWhiteSpace($packageVersion)) { throw 'AIW package version is missing' }
    $rustcText = & rustc -vV
    if ($LASTEXITCODE -ne 0) { throw 'Rust toolchain identity could not be resolved' }
    $rustcRelease = [string](($rustcText | Where-Object { $_ -like 'release:*' }) -replace '^release:\s*', '')
    $rustcHost = [string](($rustcText | Where-Object { $_ -like 'host:*' }) -replace '^host:\s*', '')
    if ([string]::IsNullOrWhiteSpace($rustcRelease) -or [string]::IsNullOrWhiteSpace($rustcHost)) {
        throw 'Rust toolchain release or host is missing'
    }

    $targetRustFlagsName = 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS'
    $targetRustFlagsPath = "Env:$targetRustFlagsName"
    $hadTargetRustFlags = Test-Path $targetRustFlagsPath
    $originalTargetRustFlags = if ($hadTargetRustFlags) {
        (Get-Item $targetRustFlagsPath).Value
    }
    else {
        $null
    }
    try {
        $targetRustFlags = (@($originalTargetRustFlags, '-C target-feature=+crt-static') |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' '
        Set-Item -Path $targetRustFlagsPath -Value $targetRustFlags
        & cargo build --locked --release -p aiw-cli
        if ($LASTEXITCODE -ne 0) { throw 'release aiw-cli build failed' }
    }
    finally {
        if ($hadTargetRustFlags) { Set-Item -Path $targetRustFlagsPath -Value $originalTargetRustFlags }
        else { Remove-Item $targetRustFlagsPath -ErrorAction SilentlyContinue }
    }

    if ($null -ne $GuestAgent -xor $null -ne $GuestAgentSha256) { throw 'GuestAgent and GuestAgentSha256 must be supplied together' }
    if ($GuestAgent) {
        Assert-LowerSha256 $GuestAgentSha256 'GuestAgentSha256'
        $guestSource = [IO.Path]::GetFullPath($GuestAgent)
        if (-not (Test-Path -LiteralPath $guestSource -PathType Leaf)) { throw "guest-agent artifact is missing: $guestSource" }
        $actualGuestHash = (Get-FileHash -LiteralPath $guestSource -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualGuestHash -ne $GuestAgentSha256) { throw 'guest-agent bytes do not match the independently retained hash' }
    } else {
        $guestBuildText = & (Join-Path $PSScriptRoot 'build-guest-agent.ps1') -Profile release | Out-String
        if ($LASTEXITCODE -ne 0) { throw 'release guest-agent build failed' }
        $guestBuild = $guestBuildText | ConvertFrom-Json
        $guestSource = [IO.Path]::GetFullPath([string]$guestBuild.artifact)
    }
    if (-not (Test-Path -LiteralPath $guestSource -PathType Leaf)) { throw "guest-agent artifact is missing: $guestSource" }
    if (-not (Test-Path -LiteralPath $cliSource -PathType Leaf)) { throw "release CLI artifact is missing: $cliSource" }
    Assert-StaticX64Pe $guestSource 'guest-agent artifact'
    Assert-StaticX64Pe $cliSource 'aiw CLI artifact'

    $manifest = Get-Content -Raw -LiteralPath $manifestSource | ConvertFrom-Json
    if ($manifest.schemaVersion -ne 'aiw.dev/admin-product-assets/v0alpha1' -or $manifest.productId -cne $productId -or
        $manifest.scenarioId -cne $scenarioIdExpected) {
        throw 'product manifest is not the selected fixed contract'
    }
    if ($null -ne $LaunchProfile -xor $null -ne $LaunchProfileSha256) { throw 'LaunchProfile and LaunchProfileSha256 must be supplied together' }
    if (($isBambu -or $isInteractive) -and $LaunchProfile) { throw 'The selected workflow does not accept a launch profile' }
    $profileSource = $null
    if ($LaunchProfile) {
        $profileSource = [IO.Path]::GetFullPath($LaunchProfile)
        if (-not (Test-Path -LiteralPath $profileSource -PathType Leaf)) { throw "launch profile is missing: $profileSource" }
        Assert-LowerSha256 $LaunchProfileSha256 'LaunchProfileSha256'
        $profile = Get-Content -Raw -LiteralPath $profileSource | ConvertFrom-Json
        if ($profile.profileSha256 -ne $LaunchProfileSha256) { throw 'launch profile JSON does not match the supplied profile hash' }
        & $cliSource package verify-wsb-launch-profile-identity `
            --profile $profileSource --profile-sha256 $LaunchProfileSha256 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'launch profile canonical identity verification failed' }
    }

    New-Item -ItemType Directory -Path $output -Force:$false | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $packagedProductRoot 'tools') -Force:$false | Out-Null
    Copy-Item -LiteralPath $cliSource -Destination (Join-Path $output 'aiw.exe')
    Copy-Item -LiteralPath $guestSource -Destination (Join-Path $packagedProductRoot 'tools\aiw-guest-agent.exe')
    Copy-Item -LiteralPath $projectSource -Destination (Join-Path $packagedProductRoot $projectFile)
    Copy-Item -LiteralPath $verifierSource -Destination (Join-Path $output 'verify-preview-package.ps1')
    Copy-Item -LiteralPath $licenseSource -Destination (Join-Path $output 'LICENSE')
    if ($profileSource) {
        $packagedProfile = Join-Path $packagedProductRoot 'launch-profile.json'
        Copy-Item -LiteralPath $profileSource -Destination $packagedProfile
        & $cliSource package verify-wsb-launch-profile-identity `
            --profile $packagedProfile --profile-sha256 $LaunchProfileSha256 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'packaged launch profile canonical identity verification failed' }
        $profile = Get-Content -Raw -LiteralPath $packagedProfile | ConvertFrom-Json
    }

    $manifest.projectPath = $projectFile
    $manifest.guestAgentPath = 'tools/aiw-guest-agent.exe'
    $manifest.projectSha256 = (Get-FileHash -LiteralPath (Join-Path $packagedProductRoot $projectFile) -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest.guestAgentSha256 = (Get-FileHash -LiteralPath (Join-Path $packagedProductRoot 'tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $compileCommand = if ($isBambu) { 'compile-bambu-export-scenario' } else { 'compile-msi-scenario' }
    $compiledText = & (Join-Path $output 'aiw.exe') provider $compileCommand `
        --project (Join-Path $packagedProductRoot $projectFile) --scenario ([string]$manifest.scenarioId) | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'packaged fixed scenario compilation failed' }
    $compiled = $compiledText | ConvertFrom-Json
    if ($profileSource) {
        if ($profile.profile.applicationSha256 -ne $compiled.scenario.applicationSha256 -or
            $profile.profile.projectRevisionSha256 -ne $compiled.projectRevisionSha256 -or
            $profile.profile.scenarioSha256 -ne $compiled.scenarioSha256 -or
            $profile.profile.guestAgentSha256 -ne $manifest.guestAgentSha256) {
            throw 'launch profile does not bind the assembled application, project, scenario, and guest agent'
        }
        $manifest | Add-Member -NotePropertyName launchProfilePath -NotePropertyValue 'launch-profile.json' -Force
        $manifest | Add-Member -NotePropertyName launchProfileSha256 -NotePropertyValue $LaunchProfileSha256 -Force
    } else {
        $manifest.PSObject.Properties.Remove('launchProfilePath')
        $manifest.PSObject.Properties.Remove('launchProfileSha256')
    }
    Write-Utf8NoBom (Join-Path $packagedProductRoot 'manifest.json') ($manifest | ConvertTo-Json -Depth 20)

    $workflowDescription = if ($isBambu) {
        'the recorded Bambu Studio 02.08.02.60 x64 EXE in Windows Sandbox, using the packaged fixed STL-to-3MF export project and guest agent.'
    }
    elseif ($isInteractive) {
        'the recorded Notepad++ 8.9.8 x64 MSI in Windows Sandbox, with one bounded UTF-8 document input, an editor open for human use, and a verified retained output after successful completion.'
    }
    elseif ($profileSource) {
        'the recorded Notepad++ 8.9.8 x64 MSI in Windows Sandbox, using the packaged fixed project, guest agent, and validated local-settings replay profile.'
    }
    else {
        'the recorded Notepad++ 8.9.8 x64 MSI in Windows Sandbox, using the packaged fixed project and guest agent without a validated replay profile.'
    }
    $profileBoundary = if ($isBambu) {
        'This package supports the fixed export assessment only; it is not a profile-bound adaptation or reusable launch package.'
    }
    elseif ($isInteractive) {
        'This package is a scratch-only interactive transfer profile. It does not preserve application state or establish a reusable isolation boundary.'
    }
    elseif ($profileSource) {
        'This package is bound to the included validated replay profile.'
    }
    else {
        'This package is assessment-only and is not profile-bound. It cannot close the profile-bound clean-host release gate.'
    }
    $readme = (Get-Content -Raw -LiteralPath $readmeTemplate).
        Replace('{{VERSION}}', $packageVersion).
        Replace('{{SOURCE_REVISION}}', $sourceRevision).
        Replace('{{TARGET}}', $targetTriple).
        Replace('{{WORKFLOW_DESCRIPTION}}', $workflowDescription).
        Replace('{{PROFILE_BOUNDARY}}', $profileBoundary)
    Write-Utf8NoBom (Join-Path $output 'README.txt') $readme.TrimEnd()
    $release = [ordered]@{
        schemaVersion = 'aiw.dev/preview-release/v0alpha1'
        version = $packageVersion
        sourceRevision = $sourceRevision
        sourceTreeClean = $sourceTreeClean
        target = $targetTriple
        toolchain = [ordered]@{ rustc = $rustcRelease; buildHost = $rustcHost }
        cliSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'aiw.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
        cliCrt = 'static'
        guest = [ordered]@{
            sha256 = [string]$manifest.guestAgentSha256
            target = $targetTriple
            crt = 'static'
            peVerification = 'dumpbinHeadersAndDependents'
        }
        product = [ordered]@{
            id = [string]$manifest.productId
            installerSha256 = [string]$compiled.scenario.applicationSha256
            projectSha256 = [string]$manifest.projectSha256
            launchProfileSha256 = if ($profileSource) { $LaunchProfileSha256 } else { $null }
        }
        supportedHost = [ordered]@{
            os = 'Windows 11 24H2 or later'
            minimumBuild = 26100
            architecture = 'x64'
            provider = 'Microsoft Windows Sandbox Store package'
            providerProtocol = 'windowsSandboxCli/v0.8.107.0'
        }
        signingStatus = 'unsignedDevelopmentPreview'
    }
    Write-Utf8NoBom (Join-Path $output 'release.json') ($release | ConvertTo-Json -Depth 20)

    if ($archive) { Assert-SourceUnchanged $sourceRevision }

    $payloadFiles = Get-ChildItem -LiteralPath $output -File -Recurse | Where-Object { $_.Name -ne 'receipt.json' } |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($output, $_.FullName).Replace('\', '/')
            [ordered]@{ path = $relative; sizeBytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        } | Sort-Object { $_.path }
    $receiptCore = [ordered]@{
        schemaVersion = 'aiw.dev/preview-package-receipt/v0alpha1'
        productId = [string]$manifest.productId
        files = @($payloadFiles)
        receiptLast = $true
    }
    $receiptHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData((Get-CanonicalJsonBytes $receiptCore))).ToLowerInvariant()
    $receipt = [ordered]@{ schemaVersion = $receiptCore.schemaVersion; productId = $receiptCore.productId; files = $receiptCore.files; receiptLast = $true; receiptSha256 = $receiptHash }
    $receiptPath = Join-Path $output 'receipt.json'
    Write-Utf8NoBom $receiptPath ($receipt | ConvertTo-Json -Depth 20)
    $verificationText = & $verifierSource -PackageRoot $output -ReceiptSha256 $receiptHash | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'assembled preview package verification failed' }
    $verification = $verificationText | ConvertFrom-Json
    if ($verification.exactInventory -ne $true) { throw 'assembled preview package inventory was not verified' }

    if ($archive) {
        Compress-Archive -Path (Join-Path $output '*') -DestinationPath $archive -CompressionLevel Optimal
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) { throw 'preview archive was not created' }
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        $archiveVerificationRoot = Join-Path $temporaryRoot "aiw-preview-archive-verify-$([guid]::NewGuid().ToString('N'))"
        if (-not $archiveVerificationRoot.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Archive verification directory escaped the temporary root'
        }
        try {
            Expand-Archive -LiteralPath $archive -DestinationPath $archiveVerificationRoot
            $extractedReceipt = Join-Path $archiveVerificationRoot 'receipt.json'
            if ((Get-FileHash -LiteralPath $extractedReceipt -Algorithm SHA256).Hash -cne
                (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash) {
                throw 'Archive receipt bytes differ from the assembled package'
            }
            $archiveVerificationText = & $verifierSource -PackageRoot $archiveVerificationRoot -ReceiptSha256 $receiptHash | Out-String
            if ($LASTEXITCODE -ne 0 -or ($archiveVerificationText | ConvertFrom-Json).exactInventory -ne $true) {
                throw 'Extracted preview archive verification failed'
            }
        }
        finally {
            Remove-Item -LiteralPath $archiveVerificationRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        Assert-SourceUnchanged $sourceRevision
        $archiveItem = Get-Item -LiteralPath $archive
        $distribution = [ordered]@{
            schemaVersion = 'aiw.dev/preview-distribution/v0alpha1'
            version = $packageVersion
            sourceRevision = $sourceRevision
            target = $targetTriple
            archive = [ordered]@{
                fileName = $archiveItem.Name
                sizeBytes = $archiveItem.Length
                sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
                format = 'zip'
            }
            receiptFileSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
            receiptSha256 = $receiptHash
            verifierSha256 = (Get-FileHash -LiteralPath (Join-Path $output 'verify-preview-package.ps1') -Algorithm SHA256).Hash.ToLowerInvariant()
            signingStatus = 'unsignedDevelopmentPreview'
            authenticity = 'notEstablished'
        }
        Write-Utf8NoBom "$archive.json" ($distribution | ConvertTo-Json -Depth 20)
        Write-Output ($distribution | ConvertTo-Json -Depth 20 -Compress)
    }
    else {
        Write-Output ($receipt | ConvertTo-Json -Depth 20 -Compress)
    }
}
finally { Pop-Location }
