#!/bin/sh
# Production fixed VM107 MSIX provider. No caller-selected VM, path, snapshot,
# command, NIC or guest script. Durable lease is outside the disposable guest.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
command=${SSH_ORIGINAL_COMMAND-}
nonce=
case "$command" in
    msix-probe) operation=probe ;;
    msix-acquire:*|msix-inspect:*|msix-completed:*|msix-isolate:*|msix-restore:*|msix-connect:*|msix-begin:*|msix-release:*)
        operation=${command%%:*}
        operation=${operation#msix-}
        nonce=${command#*:}
        test "${#nonce}" = 64
        case "$nonce" in *[!0-9a-f]*) exit 64 ;; esac
        ;;
    *) printf '%s\n' 'Unsupported production MSIX provider operation' >&2; exit 64 ;;
esac
base=/var/lib/aiw-msix-worker107
lease=$base/lease
active_lease=$lease
test "$operation" != completed || lease=$base/completed-$nonce
snapshot=aiw-msix-worker107-tls-clean-r1
mkdir -p "$base" /run/aiw-worker107
test ! -L "$base"
test "$(stat -c '%u:%a' "$base")" = '0:700'
exec 9>/run/aiw-worker107/lock
flock -x -w 10 9
run_qm() { /usr/sbin/qm "$@" 9>&-; }
stage=identity
require_worker_identity() {
    stage="${identity_context-current}:name"
    printf '%s\n' "$1" | grep -Fx 'name: aiw-worker' >/dev/null
    stage="${identity_context-current}:uuid"
    printf '%s\n' "$1" | grep -Fx 'smbios1: uuid=e5cecc90-35c2-4831-bf9c-424be23f7d4e' >/dev/null
    stage="${identity_context-current}:nic"
    printf '%s\n' "$1" | grep -Ex 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0(,link_down=1)?' >/dev/null
    stage="${identity_context-current}:os-disk"
    printf '%s\n' "$1" | grep -Fx 'scsi0: r630-fast:vm-107-disk-1,discard=on,iothread=1,size=100G,ssd=1' >/dev/null
    stage="${identity_context-current}:efi-disk"
    printf '%s\n' "$1" | grep -Fx 'efidisk0: r630-fast:vm-107-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M' >/dev/null
    stage="${identity_context-current}:tpm-disk"
    printf '%s\n' "$1" | grep -Fx 'tpmstate0: r630-fast:vm-107-disk-2,size=4M,version=v2.0' >/dev/null
    # Only observed config keys and disk-only snapshot metadata are accepted.
    # Unknown attachments (including ivshmem, serial and parallel) fail closed.
    stage="${identity_context-current}:config-keys"
    if printf '%s\n' "$1" | sed 's/:.*//' | grep -Ev '^(agent|balloon|bios|boot|cores|cpu|description|efidisk0|ide2|machine|memory|meta|name|net0|numa|onboot|ostype|scsi0|scsihw|smbios1|sockets|tags|tpmstate0|vga|vmgenid|snaptime|parent)$' >/dev/null; then
        printf '%s\n' 'Unexpected worker configuration key' >&2
        return 1
    fi
    stage="${identity_context-current}:cdrom"
    printf '%s\n' "$1" | grep -Fx 'ide2: none,media=cdrom' >/dev/null
}

config=$(run_qm config 107 --current 1)
test "$config" = "$(run_qm config 107)"
identity_context=current
require_worker_identity "$config"
snapshot_config=$(run_qm config 107 --snapshot "$snapshot")
identity_context=checkpoint
require_worker_identity "$snapshot_config"
printf '%s\n' "$snapshot_config" | grep -Fx 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1' >/dev/null
snapshot_sha=$(printf '%s\n' "$snapshot_config" | sha256sum | cut -d ' ' -f1)
if test "$operation" = acquire; then
    test ! -e "$base/completed-$nonce"
    mkdir "$lease"
    printf '%s\n' "$nonce" > "$lease/owner"
    printf '%s\n' "$snapshot_sha" > "$lease/checkpoint-sha256"
    printf '%s\n' reserved > "$lease/phase"
    sync -f "$base"
fi
if test "$operation" != probe; then
    test -d "$lease"
    test ! -L "$lease"
    test -f "$lease/owner"
    test ! -L "$lease/owner"
    test "$(cat "$lease/owner")" = "$nonce"
    test "$(cat "$lease/checkpoint-sha256")" = "$snapshot_sha"
fi
set_phase() {
    printf '%s\n' "$1" > "$lease/phase.next"
    sync -f "$lease/phase.next"
    mv "$lease/phase.next" "$lease/phase"
    sync -f "$base"
}
invalidate_restore() {
    set_phase "$1"
    rm -f "$lease/restored"
    sync -f "$base"
}
require_restored() {
    test -f "$lease/restored"
    test ! -L "$lease/restored"
    test "$(cat "$lease/restored")" = "$snapshot_sha"
}
case "$operation" in
    probe|acquire|inspect) ;;
    completed)
        require_restored
        test "$(cat "$lease/phase")" = online-clean
        ;;
    isolate)
        invalidate_restore dirty
        run_qm set 107 --net0 'virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1' >/dev/null
        ;;
    restore)
        invalidate_restore restoring
        run_qm set 107 --net0 'virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1' >/dev/null
        if test "$(run_qm status 107)" = 'status: running'; then
            if ! run_qm shutdown 107 --timeout 120; then run_qm stop 107; fi
        fi
        test "$(run_qm status 107)" = 'status: stopped'
        run_qm rollback 107 "$snapshot" >/dev/null
        restored=$(run_qm config 107 --current 1)
        identity_context=restored
        require_worker_identity "$restored"
        printf '%s\n' "$restored" | grep -Fx 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1' >/dev/null
        run_qm start 107 >/dev/null
        printf '%s\n' "$snapshot_sha" > "$lease/restored"
        sync -f "$lease/restored"
        set_phase restored
        ;;
    connect)
        require_restored
        test "$(cat "$lease/phase")" = restored
        test "$(run_qm status 107)" = 'status: running'
        run_qm set 107 --net0 'virtio=CC:34:21:B8:5A:31,bridge=vmbr0' >/dev/null
        set_phase online-clean
        ;;
    begin)
        require_restored
        test "$(cat "$lease/phase")" = online-clean
        invalidate_restore dirty
        ;;
    release)
        require_restored
        test "$(cat "$lease/phase")" = online-clean
        test "$(run_qm status 107)" = 'status: running'
        mv "$lease" "$base/completed-$nonce"
        sync -f "$base"
        ;;
esac
config=$(run_qm config 107 --current 1)
test "$config" = "$(run_qm config 107)"
identity_context=final
require_worker_identity "$config"
config_sha=$(printf '%s\n' "$config" | sha256sum | cut -d ' ' -f1)
provider_sha=$(sha256sum /usr/local/sbin/aiw-vm203 | cut -d ' ' -f1)
phase=none
test ! -d "$lease" || phase=$(cat "$lease/phase")
status=$(run_qm status 107)
case "$status" in 'status: running') running=true ;; 'status: stopped') running=false ;; *) exit 1 ;; esac
lease_present=false
test ! -e "$active_lease" || lease_present=true
printf '{"schemaVersion":"aiw.dev/vm-msix-hypervisor/v0alpha1","vmId":107,"workerUuid":"e5cecc90-35c2-4831-bf9c-424be23f7d4e","operation":"%s","nonce":"%s","checkpoint":"%s","checkpointConfigSha256":"%s","observedConfigSha256":"%s","providerSha256":"%s","phase":"%s","running":%s,"leasePresent":%s}\n' "$operation" "$nonce" "$snapshot" "$snapshot_sha" "$config_sha" "$provider_sha" "$phase" "$running" "$lease_present"
