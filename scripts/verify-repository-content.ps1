#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param([string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot))
# Read-only source guard. Application inputs and generated packages stay external.
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$paths = @(& git -C $root -c core.quotepath=false ls-files --cached --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate repository content' }
$blocked = [Collections.Generic.List[string]]::new()
$count = 0
foreach ($relative in ($paths | Sort-Object -Unique)) {
    # Git quotes control characters and literal quotes even with quotepath=false.
    # Refuse such names rather than mistaking them for absent/deleted paths.
    if ($relative.StartsWith('"')) { throw 'Quoted or control-character repository paths are not supported' }
    $path = Join-Path $root $relative
    # A tracked deletion is allowed; git history is deliberately not rewritten.
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $count++
    if ($relative -match '(?i)\.(exe|dll|msi|msp|msix|msixbundle|appx|appxbundle|cab|zip|7z|rar|nupkg|tar|tgz|gz|bz2|xz)$') {
        $blocked.Add($relative)
        continue
    }
    $stream = [IO.File]::OpenRead($path)
    try {
        $prefix = [byte[]]::new(8)
        $read = $stream.Read($prefix, 0, $prefix.Length)
        $hex = [Convert]::ToHexString($prefix, 0, $read)
        # Detect renamed PE, ZIP/MSIX, 7z, RAR, CAB and OLE/MSI payloads.
        if ($hex -match '^(4D5A|504B0304|504B0506|504B0708|377ABCAF271C|526172211A07|4D534346|D0CF11E0A1B11AE1|1F8B|FD377A585A00|425A68)') {
            $blocked.Add($relative)
        }
    } finally { $stream.Dispose() }
}
if ($blocked.Count) { throw ('Opaque application/package content is not allowed in source: ' + ($blocked -join ', ')) }
[ordered]@{passed=$true;filesChecked=$count;scope='tracked and non-ignored source files; not Git history or remote releases'} | ConvertTo-Json -Compress
