#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PortableArchive, [Parameter(Mandatory)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$builder = Join-Path $PSScriptRoot 'build-notepad-msix.ps1'
function Assert-Rejected([scriptblock]$Action, [string]$Expected) {
    $rejected = $false
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -notlike "*$Expected*") { throw }; $rejected = $true }
    if (!$rejected) { throw "Expected rejection: $Expected" }
}
$first = & $builder -PortableArchive $PortableArchive -OutputDirectory (Join-Path $EvidenceDirectory 'first') | ConvertFrom-Json
$second = & $builder -PortableArchive $PortableArchive -OutputDirectory (Join-Path $EvidenceDirectory 'second') | ConvertFrom-Json
$a = Get-Content (Join-Path $EvidenceDirectory 'first\assembly.json') -Raw | ConvertFrom-Json
$b = Get-Content (Join-Path $EvidenceDirectory 'second\assembly.json') -Raw | ConvertFrom-Json
if (($a.payloadInventory | ConvertTo-Json -Depth 8 -Compress) -cne ($b.payloadInventory | ConvertTo-Json -Depth 8 -Compress)) { throw 'Semantic payload reproducibility failed' }
# Verify actual archive payload, rather than trusting the producer's inventory.
foreach ($candidate in @($first, $second)) {
    $zip = [IO.Compression.ZipFile]::OpenRead($candidate.package)
    try {
        foreach ($file in $a.payloadInventory) {
            # MakeAppx uses OPC part names: '+' in a physical filename becomes '%2B'.
            $partName = ($file.path.Split('/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
            $entry = $zip.GetEntry($partName)
            if ($null -eq $entry -or $entry.Length -ne $file.sizeBytes) { throw "Packaged payload absent/different: $($file.path)" }
            $stream = $entry.Open()
            try { $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant() } finally { $stream.Dispose() }
            if ($hash -cne $file.sha256) { throw "Packaged payload hash differs: $($file.path)" }
        }
        if ($zip.GetEntry('Application/doLocalConf.xml') -or $null -eq $zip.GetEntry('Application/license.txt') -or $null -eq $zip.GetEntry('AppxBlockMap.xml')) { throw 'Adaptation/license/block-map contract differs' }
        if ($zip.Entries.Count -ne $a.payloadInventory.Count + 2) { throw 'Unexpected MSIX archive inventory' }
    } finally { $zip.Dispose() }
}
Assert-Rejected { & $builder -PortableArchive $PortableArchive -OutputDirectory (Join-Path $EvidenceDirectory 'first') } 'fresh output'
$tampered = Join-Path $EvidenceDirectory 'tampered.zip'
Copy-Item -LiteralPath $PortableArchive -Destination $tampered
$stream = [IO.File]::OpenWrite($tampered)
try { $stream.WriteByte(0) } finally { $stream.Dispose() }
$refused = Join-Path $EvidenceDirectory 'refused'
Assert-Rejected { & $builder -PortableArchive $tampered -OutputDirectory $refused } 'pinned Notepad'
if (Test-Path -LiteralPath $refused) { throw 'Tampered input created assembly output' }
$result = [ordered]@{ passed = $true; semanticPayloadEquivalent = $true; archivePayloadVerified = $true; existingOutputRefused = $true; tamperedSourceRefusedBeforeOutput = $true; unsignedByteHashesEqual = ($first.sha256 -ceq $second.sha256); lifecycleAcceptance = 'notRun'; evidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory) }
$result | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'checks.json') -Encoding utf8NoBOM
$result | ConvertTo-Json -Compress
