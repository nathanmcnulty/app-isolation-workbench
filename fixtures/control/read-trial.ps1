function Hash-Text([string]$Text) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant() }
function Read-BoundedJson([string]$Path) {
    $item=Get-Item -LiteralPath $Path
    if ($item.Length -gt 65536 -or $item.PSIsContainer) { throw 'Control record is oversized or not a file' }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Read-ControlTrial([string]$directory) {
    $journal=Read-BoundedJson (Join-Path $directory 'host-journal.json')
    $path=Join-Path $directory 'output\control-result.json'
    $result=Read-BoundedJson $path
    if ($journal.schemaVersion -ne 'aiw.dev/research/control-host/v0alpha1' -or !$journal.cleanupVerified -or $journal.productionEvidence -ne $false -or $result.productionEvidence -ne $false -or $result.fixtureSha256 -ne $journal.fixtureSha256 -or $result.error -or $result.stage -ne 'finished' -or !$result.windowsBuild -or !$result.standardUserSid) { throw 'Control record binding or completion failed' }
    if ((Get-FileHash $path).Hash.ToLowerInvariant() -ne $journal.resultSha256) { throw 'Control result changed' }
    $configuration=Join-Path $directory 'configuration.wsb'
    if ((Get-Item -LiteralPath $configuration).Length -gt 65536 -or (Get-FileHash -LiteralPath $configuration).Hash.ToLowerInvariant() -ne $journal.configSha256 -or $journal.providerSha256 -ne '247e092b5c5bd37820f225a7dd3ddf10ae37a67e2751a19c24b802c84769c441' -or !$journal.workspaceRoot) { throw 'Control configuration or provider binding failed' }
    $settings=[Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.MaxCharactersInDocument=65536
    $settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new((Get-Content -LiteralPath $configuration -Raw)), $settings)
    $xml=[Xml.XmlDocument]::new(); $xml.XmlResolver=$null
    try { $xml.Load($reader) } finally { $reader.Dispose() }
    $mappings=@($xml.Configuration.MappedFolders.MappedFolder)
    if ($mappings.Count -ne 2) { throw 'Unexpected control mappings' }
    for ($mapping=0; $mapping -lt 2; $mapping++) {
        $leaf=@('input','output')[$mapping]
        if ($mappings[$mapping].HostFolder -cne (Join-Path $journal.workspaceRoot $leaf)) { throw 'Control host mapping changed' }
        $mappings[$mapping].HostFolder="CONTROL-$leaf"
    }
    $normalizedConfigSha256=Hash-Text $xml.OuterXml
    if ((Get-FileHash (Join-Path $directory 'input\aiw-control-fixture.exe')).Hash.ToLowerInvariant() -ne $journal.fixtureSha256 -or (Get-FileHash (Join-Path $directory 'input\guest.ps1')).Hash.ToLowerInvariant() -ne $journal.guestScriptSha256) { throw 'Control input changed' }
    [pscustomobject]@{journal=$journal; result=$result; normalizedConfigSha256=$normalizedConfigSha256}
}
