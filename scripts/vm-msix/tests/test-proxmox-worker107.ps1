#Requires -Version 7.6
#Requires -PSEdition Core
# Isolated state-machine regression for the production forced-command wrapper.
# Rewrites only fixed host paths/authority checks in a temporary copy; qm is mocked.
$ErrorActionPreference = 'Stop'
if([Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne 'X64' -or $PSVersionTable.PSVersion.ToString() -match '-' -or $PSVersionTable.GitCommitId -match 'preview|rc'){throw 'Stable PowerShell required'}
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$sourcePath = Join-Path $repo 'scripts\vm-msix\proxmox-worker107.sh'
$sh = 'C:\Program Files\Git\usr\bin\sh.exe'
$cygpath = 'C:\Program Files\Git\usr\bin\cygpath.exe'
if (!(Test-Path -LiteralPath $sh) -or !(Test-Path -LiteralPath $cygpath)) {
    throw 'Git for Windows sh.exe and cygpath.exe are required for this isolated test'
}
$temp = Join-Path $env:TEMP ('aiw-msix-mock-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    $posix = (& $cygpath -u $temp).Trim()
    $bin = Join-Path $temp 'bin'
    $state = Join-Path $temp 'state'
    $run = Join-Path $temp 'run'
    $null = New-Item -ItemType Directory -Path $bin, $state, $run
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $state 'status'), "running`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $state 'nic'), "down`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $state 'name'), "aiw-worker`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $state 'uuid'), "e5cecc90-35c2-4831-bf9c-424be23f7d4e`n", $utf8)

    $qm = @'
#!/bin/sh
set -eu
state=${AIW_MOCK_STATE:?}
op=$1
test "$2" = 107 || exit 91
printf '%s\n' "$*" >> "$state/calls"
case "$op" in
  config)
    name=$(cat "$state/name")
    uuid=$(cat "$state/uuid")
    nic=$(cat "$state/nic")
    if test "${3-}" = --snapshot; then
      test "${4-}" = aiw-msix-worker107-core76plus-clean-r2 || exit 92
      nic=down
      name=aiw-worker
      uuid=e5cecc90-35c2-4831-bf9c-424be23f7d4e
    elif test "${3-}" != --current && test -f "$state/pending-name"; then
      name=$(cat "$state/pending-name")
    fi
    printf 'name: %s\n' "$name"
    printf 'smbios1: uuid=%s\n' "$uuid"
    if test "$nic" = down; then
      printf '%s\n' 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1'
    else
      printf '%s\n' 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0'
    fi
    printf '%s\n' 'scsi0: r630-fast:vm-107-disk-1,discard=on,iothread=1,size=100G,ssd=1'
    printf '%s\n' 'efidisk0: r630-fast:vm-107-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M'
    printf '%s\n' 'tpmstate0: r630-fast:vm-107-disk-2,size=4M,version=v2.0'
    printf '%s\n' 'ide2: none,media=cdrom'
    if test "${3-}" = --snapshot && test -f "$state/snapshot-description"; then
      printf 'description: %s\n' "$(cat "$state/snapshot-description")"
    fi
    ;;
  status) printf 'status: %s\n' "$(cat "$state/status")" ;;
  set)
    test "${3-}" = --net0 || exit 93
    test ! -f "$state/fail-set" || exit 94
    case "${4-}" in
      'virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1') printf 'down\n' > "$state/nic" ;;
      'virtio=CC:34:21:B8:5A:31,bridge=vmbr0') printf 'up\n' > "$state/nic" ;;
      *) exit 95 ;;
    esac
    ;;
  shutdown|stop) printf 'stopped\n' > "$state/status" ;;
  rollback)
    test "${3-}" = aiw-msix-worker107-core76plus-clean-r2 || exit 96
    test ! -f "$state/fail-rollback" || exit 97
    printf 'down\n' > "$state/nic"
    printf 'rollback\n' >> "$state/rollbacks"
    ;;
  start) printf 'running\n' > "$state/status" ;;
  *) exit 98 ;;
esac
'@
    [IO.File]::WriteAllText((Join-Path $bin 'qm'), $qm.Replace("`r`n", "`n") + "`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $bin 'sync'), "#!/bin/sh`nprintf 'sync\n' >> `"`$AIW_MOCK_STATE/sync-calls`"`n", $utf8)

    $source = [IO.File]::ReadAllText($sourcePath)
    function Replace-Once([string]$old, [string]$new) {
        $count = [regex]::Matches($script:source, [regex]::Escape($old)).Count
        if ($count -ne 1) { throw "Expected one test substitution for [$old], found $count" }
        $script:source = $script:source.Replace($old, $new)
    }
    Replace-Once 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "PATH=$posix/bin:/usr/bin:/bin"
    Replace-Once 'test "$(id -u)" = 0' ':'
    Replace-Once 'test "$(hostname -s)" = pve-r630' ':'
    Replace-Once 'base=/var/lib/aiw-msix-worker107' "base=$posix/state"
    Replace-Once 'mkdir -p "$base" /run/aiw-worker107' "mkdir -p `"`$base`" $posix/run"
    Replace-Once 'test "$(stat -c ''%u:%a'' "$base")" = ''0:700''' ':'
    Replace-Once 'exec 9>/run/aiw-worker107/lock' "exec 9>$posix/run/lock"
    Replace-Once 'flock -x -w 10 9' ':'
    Replace-Once 'run_qm() { /usr/sbin/qm "$@" 9>&-; }' "run_qm() { /usr/bin/sh $posix/bin/qm `"`$@`" 9>&-; }"
    Replace-Once '/usr/local/sbin/aiw-vm203' "$posix/wrapper.sh"
    $wrapper = Join-Path $temp 'wrapper.sh'
    [IO.File]::WriteAllText($wrapper, $source.Replace("`r`n", "`n"), $utf8)
    $env:AIW_MOCK_STATE = "$posix/state"

    function Invoke-Mock([string]$request) {
        $env:SSH_ORIGINAL_COMMAND = $request
        $output = @(& $sh "$posix/wrapper.sh" 2>&1)
        $exit = $LASTEXITCODE
        [pscustomobject]@{ ExitCode = $exit; Output = ($output -join "`n") }
    }
    function Expect-Success([string]$request, [string]$phase, [bool]$leasePresent) {
        $result = Invoke-Mock $request
        if ($result.ExitCode -ne 0) { throw "$request failed ($($result.ExitCode)): $($result.Output)" }
        $json = $result.Output | ConvertFrom-Json
        if ($json.phase -cne $phase -or $json.leasePresent -ne $leasePresent) {
            throw "$request returned phase=$($json.phase), leasePresent=$($json.leasePresent)"
        }
        if ($json.vmId -ne 107 -or $json.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e') {
            throw "$request returned wrong VM identity"
        }
        if ($json.providerSha256 -cnotmatch '^[0-9a-f]{64}$') { throw "$request omitted provider hash" }
        return $json
    }
    function Expect-Failure([string]$request) {
        $result = Invoke-Mock $request
        if ($result.ExitCode -eq 0) { throw "$request unexpectedly succeeded: $($result.Output)" }
    }
    $n1 = 'a' * 64
    $n2 = 'b' * 64
    $null = Expect-Success 'msix-probe' 'none' $false
    Expect-Failure "msix-acquire:$n1;touch /tmp/escape"
    $null = Expect-Success "msix-acquire:$n1" 'reserved' $true
    Expect-Failure "msix-acquire:$n2"
    Expect-Failure "msix-inspect:$n2"
    Expect-Failure "msix-connect:$n1"
    Expect-Failure "msix-release:$n1"
    $restored = Expect-Success "msix-restore:$n1" 'restored' $true
    Expect-Failure "msix-release:$n1"
    $online = Expect-Success "msix-connect:$n1" 'online-clean' $true
    if ($online.observedConfigSha256 -ceq $restored.observedConfigSha256) {
        throw 'Connect returned stale pre-operation config hash'
    }
    $null = Expect-Success "msix-begin:$n1" 'dirty' $true
    Expect-Failure "msix-release:$n1"
    Expect-Failure "msix-connect:$n1"
    $null = Expect-Success "msix-restore:$n1" 'restored' $true
    $null = Expect-Success "msix-connect:$n1" 'online-clean' $true
    $null = Expect-Success "msix-release:$n1" 'none' $false
    if (!(Test-Path -LiteralPath (Join-Path $state "completed-$n1"))) { throw 'Completed nonce audit missing' }
    Expect-Failure "msix-acquire:$n1"
    $null = Expect-Success "msix-completed:$n1" 'online-clean' $false
    Expect-Failure "msix-completed:$n2"

    $null = Expect-Success "msix-acquire:$n2" 'reserved' $true
    [IO.File]::WriteAllText((Join-Path $state 'fail-rollback'), '', $utf8)
    Expect-Failure "msix-restore:$n2"
    if ((Get-Content (Join-Path $state 'lease\phase') -Raw).Trim() -cne 'restoring') {
        throw 'Failed rollback did not preserve restoring phase'
    }
    Expect-Failure "msix-release:$n2"
    Remove-Item -LiteralPath (Join-Path $state 'fail-rollback')
    $null = Expect-Success "msix-restore:$n2" 'restored' $true
    [IO.File]::WriteAllText((Join-Path $state 'snapshot-description'), "changed`n", $utf8)
    Expect-Failure "msix-inspect:$n2"
    Remove-Item -LiteralPath (Join-Path $state 'snapshot-description')
    [IO.File]::WriteAllText((Join-Path $state 'uuid'), "00000000-0000-0000-0000-000000000000`n", $utf8)
    Expect-Failure 'msix-probe'
    [IO.File]::WriteAllText((Join-Path $state 'uuid'), "e5cecc90-35c2-4831-bf9c-424be23f7d4e`n", $utf8)
    [IO.File]::WriteAllText((Join-Path $state 'pending-name'), "other`n", $utf8)
    Expect-Failure 'msix-probe'
    Remove-Item -LiteralPath (Join-Path $state 'pending-name')
    $null = Expect-Success "msix-connect:$n2" 'online-clean' $true
    $null = Expect-Success "msix-release:$n2" 'none' $false
    if (@(Get-Content (Join-Path $state 'rollbacks')).Count -ne 3) { throw 'Unexpected rollback count' }
    if (@(Get-Content (Join-Path $state 'sync-calls')).Count -lt 4) { throw 'Durability sync calls missing' }
    Write-Output 'PASS: VM107 forced-command state transitions, failed restore, nonce reuse, identity and checkpoint guards'
}
finally {
    Remove-Item Env:AIW_MOCK_STATE, Env:SSH_ORIGINAL_COMMAND -ErrorAction SilentlyContinue
    $absolute = [IO.Path]::GetFullPath($temp)
    $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
    if (!$absolute.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
        !(Split-Path -Leaf $absolute).StartsWith('aiw-msix-mock-', [StringComparison]::Ordinal)) {
        throw "Refusing to remove unexpected test path: $absolute"
    }
    Remove-Item -LiteralPath $absolute -Recurse -Force
}
