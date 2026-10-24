#Requires -Version 7.6
#Requires -PSEdition Core
# Execute the production Collect remoting body against an isolated, ordinary
# temporary profile tree. No WinRM session, worker, application or account is used.
$ErrorActionPreference = 'Stop'
if([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSVersionTable.PSVersion.ToString() -match '-' -or $PSVersionTable.GitCommitId -match 'preview|rc'){throw 'Stable PowerShell required'}
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$transport = Join-Path $repo 'scripts\vm-msix\transport.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($transport, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw "Production transport does not parse: $($errors | Out-String)" }

# Select the one Invoke-Command in the actual Collect branch. Do not keep a
# parallel copy of the export implementation in this test.
$branches = @($ast.FindAll({
    param($node)
    if ($node -isnot [Management.Automation.Language.IfStatementAst]) { return $false }
    @($node.Clauses | Where-Object { $_.Item1.Extent.Text -cmatch '\$Operation\s+-eq\s+''Collect''' }).Count -eq 1
}, $true))
if ($branches.Count -ne 1) { throw "Expected one closed Collect branch, found $($branches.Count)" }
$clause = @($branches[0].Clauses | Where-Object { $_.Item1.Extent.Text -cmatch '\$Operation\s+-eq\s+''Collect''' })[0]
$commands = @($clause.Item2.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Invoke-Command'
}, $true))
if ($commands.Count -ne 1) { throw "Expected one Collect Invoke-Command, found $($commands.Count)" }
$scriptBlocks = @($commands[0].CommandElements | Where-Object {
    $_ -is [Management.Automation.Language.ScriptBlockExpressionAst]
})
if ($scriptBlocks.Count -ne 1) { throw 'Collect must have one literal remoting ScriptBlock' }
$literal = $scriptBlocks[0].ScriptBlock.Extent.Text
if (!$literal.StartsWith('{') -or !$literal.EndsWith('}')) { throw 'Collect remoting body is not literal' }
$collect = [ScriptBlock]::Create($literal.Substring(1, $literal.Length - 2))

$script:nonce = 'a' * 64
$script:sid = 'S-1-5-21-3556347314-2314855617-1438300668-2000'
$script:taskState = 'Ready'
$script:profileEnumerationFails = $false
$script:profilePath = $null
$script:root = $null

function Get-ScheduledTask {
    [pscustomobject]@{ TaskName = 'AIW-Msix-run-report-test'; State = $script:taskState }
}
function Get-Process {
    param([string[]]$Name, $ErrorAction)
    @()
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    if ($script:profileEnumerationFails) { throw 'mock-profile-enumeration-failure' }
    if ($ClassName -cne 'Win32_UserProfile') { throw "Unexpected CIM class: $ClassName" }
    [pscustomobject]@{
        SID = $script:sid
        LocalPath = $script:profilePath
        Loaded = $true
        Special = $false
    }
}

function Invoke-Collect {
    $output = @(& $collect $script:root $script:nonce)
    if ($output.Count -ne 1) { throw "Collect returned $($output.Count) objects" }
    $output[0]
}
function Expect-Rejection([string]$label, [string]$message) {
    $failure = $null
    try { $null = Invoke-Collect } catch { $failure = $_.Exception.Message }
    if (!$failure -or $failure -notmatch $message) {
        throw "$label should fail with [$message], observed [$failure]"
    }
}
function Write-Bytes([string]$path, [byte[]]$bytes) {
    $parent = Split-Path -Parent $path
    $null = New-Item -ItemType Directory -Path $parent -Force
    [IO.File]::WriteAllBytes($path, $bytes)
}
function Authoritative-Path {
    Join-Path $script:profilePath ("AppData\Local\AIW\msix-" + $script:nonce)
}
function Assert-RawExport($result, [hashtable]$expected) {
    if ($result.nonce -cne $script:nonce -or !$result.quiescent -or !$result.enumerationComplete) {
        throw 'Collect did not establish complete quiescent export'
    }
    $raw = $result.rawEvidence
    if (!$raw.complete -or $raw.source -cne 'runOwnedProfile' -or $raw.nonce -cne $script:nonce -or
        $raw.userSid -cne $script:sid -or !$raw.present) {
        throw 'Authoritative profile evidence manifest differs'
    }
    $manifest = @($raw.files)
    $records = @($result.files)
    $rawRecords = @($records | Where-Object { $_.path -like 'raw/*' })
    if ($manifest.Count -ne $expected.Count -or $rawRecords.Count -ne $expected.Count) {
        throw "Expected $($expected.Count) authoritative files; manifest=$($manifest.Count), export=$($rawRecords.Count)"
    }
    if (@($records | Where-Object { $_.path -in @('account.json', 'request.json') }).Count -ne 0) {
        throw 'Account or request material was exported'
    }
    foreach ($path in $expected.Keys) {
        $entries = @($rawRecords | Where-Object path -CEQ $path)
        $declared = @($manifest | Where-Object path -CEQ $path)
        if ($entries.Count -ne 1 -or $declared.Count -ne 1) { throw "Missing or duplicate authoritative file: $path" }
        $bytes = [Convert]::FromBase64String($entries[0].base64)
        $hash = [Security.Cryptography.SHA256]::Create()
        try { $sha = ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
        finally { $hash.Dispose() }
        if (($bytes -join ',') -cne ($expected[$path] -join ',') -or
            $entries[0].bytes -ne $bytes.Length -or $entries[0].sha256 -cne $sha -or
            $declared[0].bytes -ne $bytes.Length -or $declared[0].sha256 -cne $sha) {
            throw "Authoritative bytes or digest differ: $path"
        }
    }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('aiw-msix-export-test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
$exclusive = $null
try {
    $script:root = Join-Path $temp 'worker'
    $script:profilePath = Join-Path $temp 'profile'
    $null = New-Item -ItemType Directory -Path $script:root, $script:profilePath
    $account = @{
        runNonce = $script:nonce
        userSid = $script:sid
        workerUuid = 'e5cecc90-35c2-4831-bf9c-424be23f7d4e'
        created = $true
    }
    $account | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $script:root 'account.json') -Encoding UTF8
    $source = Authoritative-Path
    $one = [Text.Encoding]::UTF8.GetBytes('authoritative-first')
    $two = [Text.Encoding]::UTF8.GetBytes('authoritative-second')
    Write-Bytes (Join-Path $source 'msix-lifecycle\result.json') $one
    Write-Bytes (Join-Path $source 'configuration\config.xml') $two
    $expected = @{
        'raw/msix-lifecycle/result.json' = $one
        'raw/configuration/config.xml' = $two
    }

    # An old prepared workspace can have no cached evidence directory at all.
    Assert-RawExport (Invoke-Collect) $expected

    # The old format retained only controller copies under evidence/.
    Write-Bytes (Join-Path $script:root 'evidence\old-format.json') ([Text.Encoding]::UTF8.GetBytes('old-cache'))
    Assert-RawExport (Invoke-Collect) $expected

    # Neither an incomplete cache nor stale bytes can substitute for the
    # run-owned profile tree. The authoritative source still has both files.
    Write-Bytes (Join-Path $script:root 'raw\msix-lifecycle\result.json') ([Text.Encoding]::UTF8.GetBytes('stale-partial-copy'))
    Assert-RawExport (Invoke-Collect) $expected

    # Once application dispatch exists, losing the authoritative source may
    # not be mistaken for an intentionally empty pre-Run export.
    $hidden = Join-Path $temp 'temporarily-hidden-source'
    Move-Item -LiteralPath $source -Destination $hidden
    Write-Bytes (Join-Path $script:root 'run-dispatch.json') ([Text.Encoding]::UTF8.GetBytes('{}'))
    Expect-Rejection 'dispatched run without authoritative source' 'authoritative raw evidence absent'
    Move-Item -LiteralPath $hidden -Destination $source
    Remove-Item -LiteralPath (Join-Path $script:root 'run-dispatch.json')

    $script:taskState = 'Queued'
    Expect-Rejection 'queued task' 'running|queued|quiescen|task'
    $script:taskState = 'Running'
    Expect-Rejection 'running task' 'running|quiescen|task'
    $script:taskState = 'Ready'

    $script:profileEnumerationFails = $true
    Expect-Rejection 'profile enumeration failure' 'mock-profile-enumeration-failure'
    $script:profileEnumerationFails = $false

    # Windows sharing denial is a real read failure without changing ACLs or
    # replacing the production filesystem commands with mocks.
    $exclusive = [IO.File]::Open((Join-Path $source 'configuration\config.xml'),
        [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    Expect-Rejection 'authoritative file read failure' 'access|sharing|used by another process|read|evidence'
    $exclusive.Dispose(); $exclusive = $null
    Assert-RawExport (Invoke-Collect) $expected

    Write-Output 'PASS: production Collect exports run-owned raw evidence independently of cache; queued work and source failures fail closed'
}
finally {
    if ($exclusive) { $exclusive.Dispose() }
    $absolute = [IO.Path]::GetFullPath($temp)
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (!$absolute.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase) -or
        !(Split-Path -Leaf $absolute).StartsWith('aiw-msix-export-test-', [StringComparison]::Ordinal)) {
        throw "Refusing to remove unexpected test path: $absolute"
    }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
