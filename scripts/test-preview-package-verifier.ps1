[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'verify-preview-package.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) "aiw-preview-verifier-$([guid]::NewGuid().ToString('N'))"

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Get-CanonicalJsonBytes([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    return ,([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-LowerSha256([byte[]]$Bytes) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Assert-Rejected([scriptblock]$Operation, [string]$Case) {
    try {
        & $Operation | Out-Null
    }
    catch {
        return
    }
    throw "Preview package verifier accepted $Case"
}

function Assert-RejectedMessage([scriptblock]$Operation, [string]$Case, [string]$Pattern) {
    try {
        & $Operation | Out-Null
    }
    catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "Preview package verifier rejected $Case for the wrong reason: $($_.Exception.Message)"
        }
        return
    }
    throw "Preview package verifier accepted $Case"
}

try {
    $productRoot = Join-Path $root 'product\notepad-plus-plus'
    New-Item -ItemType Directory -Path (Join-Path $productRoot 'tools') -Force | Out-Null
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixed-cli-bytes'
    Write-Utf8NoBom (Join-Path $productRoot 'project.yaml') 'fixed-project-bytes'
    Write-Utf8NoBom (Join-Path $productRoot 'tools\aiw-guest-agent.exe') 'fixed-guest-bytes'
    $manifest = [ordered]@{
        schemaVersion = 'aiw.dev/admin-product-assets/v0alpha1'
        productId = 'notepad-plus-plus-local-settings'
        projectPath = 'project.yaml'
        projectSha256 = (Get-FileHash -LiteralPath (Join-Path $productRoot 'project.yaml') -Algorithm SHA256).Hash.ToLowerInvariant()
        guestAgentPath = 'tools/aiw-guest-agent.exe'
        guestAgentSha256 = (Get-FileHash -LiteralPath (Join-Path $productRoot 'tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
        scenarioId = 'install-launch-close'
    }
    Write-Utf8NoBom (Join-Path $productRoot 'manifest.json') ($manifest | ConvertTo-Json -Depth 20)
    $records = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
        [ordered]@{
            path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            sizeBytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object { $_.path })
    $core = [ordered]@{
        schemaVersion = 'aiw.dev/preview-package-receipt/v0alpha1'
        productId = 'notepad-plus-plus-local-settings'
        files = $records
        receiptLast = $true
    }
    $receiptSha256 = Get-LowerSha256 (Get-CanonicalJsonBytes $core)
    $receipt = [ordered]@{
        schemaVersion = $core.schemaVersion
        productId = $core.productId
        files = $core.files
        receiptLast = $true
        receiptSha256 = $receiptSha256
    }
    Write-Utf8NoBom (Join-Path $root 'receipt.json') ($receipt | ConvertTo-Json -Depth 20)

    $verified = & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 | ConvertFrom-Json
    if ($verified.exactInventory -ne $true -or $verified.filesVerified -ne 4) {
        throw 'Preview package verifier did not confirm the valid fixture'
    }
    # In-process PowerShell scripts throw on failure; LASTEXITCODE belongs to
    # the most recent native process and must not decide verifier success.
    & $env:ComSpec /d /c 'exit 17'
    $staleExitVerification = & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 | ConvertFrom-Json
    if ($staleExitVerification.exactInventory -ne $true -or $LASTEXITCODE -ne 17) {
        throw 'Preview verification incorrectly depends on a previous native exit code'
    }
    Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $unsetExitVerification = & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 | ConvertFrom-Json
    if ($unsetExitVerification.exactInventory -ne $true -or $null -ne $LASTEXITCODE) {
        throw 'Preview verification incorrectly depends on an initialized native exit code'
    }
    Push-Location -LiteralPath $root
    try {
        $relativeVerification = & $verifier -PackageRoot . -ReceiptSha256 $receiptSha256 | ConvertFrom-Json
        if ($relativeVerification.exactInventory -ne $true -or $relativeVerification.filesVerified -ne 4) {
            throw 'Preview package verifier did not resolve a relative package root from the PowerShell location'
        }
    }
    finally {
        Pop-Location
    }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
        throw 'Windows PowerShell is required for the clean-host verifier compatibility check'
    }
    $windowsVerificationText = & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell preview package verification failed' }
    $windowsVerification = $windowsVerificationText | ConvertFrom-Json
    if ($windowsVerification.exactInventory -ne $true -or $windowsVerification.filesVerified -ne 4) {
        throw 'Windows PowerShell did not confirm the valid preview package fixture'
    }
    $staleExitCommand = "& `$env:ComSpec /d /c 'exit 17'; `$verified = & '$($verifier.Replace("'", "''"))' -PackageRoot '$($root.Replace("'", "''"))' -ReceiptSha256 '$receiptSha256' | ConvertFrom-Json; if (`$verified.exactInventory -ne `$true -or `$LASTEXITCODE -ne 17) { throw 'Stale native exit code affected verification' }; Remove-Variable LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue; `$verified = & '$($verifier.Replace("'", "''"))' -PackageRoot '$($root.Replace("'", "''"))' -ReceiptSha256 '$receiptSha256' | ConvertFrom-Json; if (`$verified.exactInventory -ne `$true -or `$null -ne `$LASTEXITCODE) { throw 'Unset native exit code affected verification' }; `$verified | ConvertTo-Json -Compress; exit 0"
    $staleExitEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($staleExitCommand))
    $staleExitText = & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $staleExitEncoded | Out-String
    if ($LASTEXITCODE -ne 0 -or ($staleExitText | ConvertFrom-Json).exactInventory -ne $true) {
        throw 'Windows PowerShell stale-exit-code verification control failed'
    }
    $windowsRelativeCommand = "Set-Location -LiteralPath '$($root.Replace("'", "''"))'; & '$($verifier.Replace("'", "''"))' -PackageRoot . -ReceiptSha256 '$receiptSha256'"
    $windowsRelativeEncoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($windowsRelativeCommand))
    $windowsRelativeText = & $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -EncodedCommand $windowsRelativeEncoded | Out-String
    if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell relative-root preview package verification failed' }
    $windowsRelativeVerification = $windowsRelativeText | ConvertFrom-Json
    if ($windowsRelativeVerification.exactInventory -ne $true -or $windowsRelativeVerification.filesVerified -ne 4) {
        throw 'Windows PowerShell did not resolve a relative package root from its PowerShell location'
    }

    $receiptPath = Join-Path $root 'receipt.json'
    $originalReceiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    $movedPayload = Join-Path ([IO.Path]::GetTempPath()) "aiw-preview-moved-$([guid]::NewGuid().ToString('N'))"
    Move-Item -LiteralPath (Join-Path $root 'aiw.exe') -Destination $movedPayload
    try {
        Assert-RejectedMessage { & $verifier -PackageRoot $root -ReceiptSha256 ('0' * 64) } `
            'a wrong independent receipt identity before payload lookup' 'receipt identity differs'
    }
    finally {
        Move-Item -LiteralPath $movedPayload -Destination (Join-Path $root 'aiw.exe')
    }

    $unsafeCore = [ordered]@{
        schemaVersion = $core.schemaVersion
        productId = $core.productId
        files = @([ordered]@{ path = '../outside'; sizeBytes = 0; sha256 = '0' * 64 })
        receiptLast = $true
    }
    $unsafeHash = Get-LowerSha256 (Get-CanonicalJsonBytes $unsafeCore)
    Write-Utf8NoBom $receiptPath (([ordered]@{
        schemaVersion = $unsafeCore.schemaVersion; productId = $unsafeCore.productId
        files = $unsafeCore.files; receiptLast = $true; receiptSha256 = $unsafeHash
    }) | ConvertTo-Json -Depth 20)
    Assert-RejectedMessage { & $verifier -PackageRoot $root -ReceiptSha256 $unsafeHash } `
        'an unsafe receipt path' 'unsafe path'

    $duplicateCore = [ordered]@{
        schemaVersion = $core.schemaVersion
        productId = $core.productId
        files = @(
            [ordered]@{ path = 'AIW.exe'; sizeBytes = 1; sha256 = '0' * 64 },
            [ordered]@{ path = 'aiw.exe'; sizeBytes = 1; sha256 = '0' * 64 }
        )
        receiptLast = $true
    }
    $duplicateHash = Get-LowerSha256 (Get-CanonicalJsonBytes $duplicateCore)
    Write-Utf8NoBom $receiptPath (([ordered]@{
        schemaVersion = $duplicateCore.schemaVersion; productId = $duplicateCore.productId
        files = $duplicateCore.files; receiptLast = $true; receiptSha256 = $duplicateHash
    }) | ConvertTo-Json -Depth 20)
    Assert-RejectedMessage { & $verifier -PackageRoot $root -ReceiptSha256 $duplicateHash } `
        'case-colliding receipt paths' 'duplicate paths'
    [IO.File]::WriteAllBytes($receiptPath, $originalReceiptBytes)

    $rootJunction = "$root-junction"
    New-Item -ItemType Junction -Path $rootJunction -Target $root | Out-Null
    try {
        Assert-RejectedMessage { & $verifier -PackageRoot $rootJunction -ReceiptSha256 $receiptSha256 } `
            'a reparse-point package root' 'root is a reparse point'
    }
    finally {
        Remove-Item -LiteralPath $rootJunction -Force -ErrorAction SilentlyContinue
    }

    $outside = "$root-outside"
    New-Item -ItemType Directory -Path $outside | Out-Null
    Write-Utf8NoBom (Join-Path $outside 'linked.txt') 'linked'
    $linked = Get-Item -LiteralPath (Join-Path $outside 'linked.txt')
    $junction = Join-Path $root 'linked'
    New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
    try {
        $junctionRecords = @($records + @([ordered]@{
            path = 'linked/linked.txt'; sizeBytes = $linked.Length
            sha256 = (Get-FileHash -LiteralPath $linked.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })) | Sort-Object { $_.path }
        $junctionCore = [ordered]@{
            schemaVersion = $core.schemaVersion; productId = $core.productId
            files = $junctionRecords; receiptLast = $true
        }
        $junctionHash = Get-LowerSha256 (Get-CanonicalJsonBytes $junctionCore)
        Write-Utf8NoBom $receiptPath (([ordered]@{
            schemaVersion = $junctionCore.schemaVersion; productId = $junctionCore.productId
            files = $junctionCore.files; receiptLast = $true; receiptSha256 = $junctionHash
        }) | ConvertTo-Json -Depth 20)
        Assert-RejectedMessage { & $verifier -PackageRoot $root -ReceiptSha256 $junctionHash } `
            'an intermediate payload junction' 'payload parent is a reparse point'
    }
    finally {
        Remove-Item -LiteralPath $junction -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $outside -Recurse -Force -ErrorAction SilentlyContinue
        [IO.File]::WriteAllBytes($receiptPath, $originalReceiptBytes)
    }

    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'changed-cli-bytes'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 } 'changed payload bytes'
    Write-Utf8NoBom (Join-Path $root 'aiw.exe') 'fixed-cli-bytes'

    Write-Utf8NoBom (Join-Path $root 'unexpected.txt') 'unexpected'
    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 $receiptSha256 } 'an unexpected file'
    Remove-Item -LiteralPath (Join-Path $root 'unexpected.txt')

    Assert-Rejected { & $verifier -PackageRoot $root -ReceiptSha256 ('0' * 64) } 'a wrong independent receipt identity'

    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $bambuRoot = [IO.Path]::GetFullPath((Join-Path $tempPrefix "aiw-bambu-verifier-$([guid]::NewGuid().ToString('N'))"))
    if (-not $bambuRoot.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Bambu verifier fixture escaped the temporary root'
    }
    try {
        $bambuProduct = Join-Path $bambuRoot 'product\bambu-studio'
        New-Item -ItemType Directory -Path (Join-Path $bambuProduct 'tools') -Force | Out-Null
        Write-Utf8NoBom (Join-Path $bambuRoot 'aiw.exe') 'fixed-cli-bytes'
        Write-Utf8NoBom (Join-Path $bambuProduct 'project.json') '{"fixed":"bambu"}'
        Write-Utf8NoBom (Join-Path $bambuProduct 'tools\aiw-guest-agent.exe') 'fixed-guest-bytes'
        $bambuManifest = [ordered]@{
            schemaVersion = 'aiw.dev/admin-product-assets/v0alpha1'
            productId = 'bambu-studio-export'
            projectPath = 'project.json'
            projectSha256 = (Get-FileHash -LiteralPath (Join-Path $bambuProduct 'project.json') -Algorithm SHA256).Hash.ToLowerInvariant()
            guestAgentPath = 'tools/aiw-guest-agent.exe'
            guestAgentSha256 = (Get-FileHash -LiteralPath (Join-Path $bambuProduct 'tools\aiw-guest-agent.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
            scenarioId = 'local-file-export'
        }
        Write-Utf8NoBom (Join-Path $bambuProduct 'manifest.json') ($bambuManifest | ConvertTo-Json -Depth 20)
        $bambuRecords = @(Get-ChildItem -LiteralPath $bambuRoot -Recurse -File | ForEach-Object {
            [ordered]@{
                path = [IO.Path]::GetRelativePath($bambuRoot, $_.FullName).Replace('\', '/')
                sizeBytes = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        } | Sort-Object { $_.path })
        $bambuCore = [ordered]@{
            schemaVersion = 'aiw.dev/preview-package-receipt/v0alpha1'
            productId = 'bambu-studio-export'
            files = $bambuRecords
            receiptLast = $true
        }
        $bambuHash = Get-LowerSha256 (Get-CanonicalJsonBytes $bambuCore)
        Write-Utf8NoBom (Join-Path $bambuRoot 'receipt.json') (([ordered]@{
            schemaVersion = $bambuCore.schemaVersion
            productId = $bambuCore.productId
            files = $bambuCore.files
            receiptLast = $true
            receiptSha256 = $bambuHash
        }) | ConvertTo-Json -Depth 20)
        $bambuVerified = & $verifier -PackageRoot $bambuRoot -ReceiptSha256 $bambuHash | ConvertFrom-Json
        if ($bambuVerified.exactInventory -ne $true -or $bambuVerified.filesVerified -ne 4) {
            throw 'Bambu preview package fixture was not verified'
        }
        $bambuManifest.launchProfilePath = ''
        Write-Utf8NoBom (Join-Path $bambuProduct 'manifest.json') ($bambuManifest | ConvertTo-Json -Depth 20)
        $bambuRecords = @(Get-ChildItem -LiteralPath $bambuRoot -Recurse -File |
            Where-Object { $_.Name -ne 'receipt.json' } | ForEach-Object {
                [ordered]@{
                    path = [IO.Path]::GetRelativePath($bambuRoot, $_.FullName).Replace('\', '/')
                    sizeBytes = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            } | Sort-Object { $_.path })
        $bambuCore.files = $bambuRecords
        $bambuHash = Get-LowerSha256 (Get-CanonicalJsonBytes $bambuCore)
        Write-Utf8NoBom (Join-Path $bambuRoot 'receipt.json') (([ordered]@{
            schemaVersion = $bambuCore.schemaVersion
            productId = $bambuCore.productId
            files = $bambuCore.files
            receiptLast = $true
            receiptSha256 = $bambuHash
        }) | ConvertTo-Json -Depth 20)
        Assert-RejectedMessage { & $verifier -PackageRoot $bambuRoot -ReceiptSha256 $bambuHash } `
            'a present but empty Bambu launch profile' 'fixed contract'
    }
    finally {
        Remove-Item -LiteralPath $bambuRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'Preview package verifier contract passed.' -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
