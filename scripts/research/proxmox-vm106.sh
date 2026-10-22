#!/bin/sh
# Closed research controller for the isolated Proxmox VM 106 worker.
# Root-owned, forced-command only; no caller arguments or arbitrary shell text.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect|status|shutdown|start|snapshot|rollback) ;;
    *) printf '%s\n' 'Unsupported VM 106 operation' >&2; exit 64 ;;
esac

# /run is root-controlled; this serializes calls through this helper only.
mkdir -p /run/aiw-vm106
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9

verify_config() {
    # Fixed fields observed by the operator on 2026-10-21. Fail closed on drift.
    for expected in \
        'name: passkeys-worker' \
        'smbios1: uuid=7e686bee-8c05-43c7-9603-a9562ece224c' \
        'efidisk0: r630-fast2:vm-106-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M' \
        'scsi0: r630-fast2:vm-106-disk-1,discard=on,iothread=1,size=100G,ssd=1' \
        'tpmstate0: r630-fast2:vm-106-disk-2,size=4M,version=v2.0' \
        'net0: virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1' \
        'onboot: 0' \
        'agent: 1'; do
        printf '%s\n' "$1" | grep -Fx "$expected" >/dev/null || return 1
    done
    # Alternate network devices and host execution hooks are outside this boundary.
    if printf '%s\n' "$1" | grep -E '^(net[1-9][0-9]*|args|hostpci[0-9]+|usb[0-9]+|hookscript):' >/dev/null; then
        return 1
    fi
}

config=$(qm config 106 --current 1)
# Reject pending changes, including fields not explicitly pinned above.
test "$config" = "$(qm config 106)"
verify_config "$config"
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect)
        printf '%s\n' "$config"
        qm status 106
        qm listsnapshot 106
        pvesm status --storage r630-fast2
        ;;
    status) qm status 106 ;;
    shutdown) qm shutdown 106 --timeout 120 ;;
    start) qm start 106 ;;
    snapshot)
        test "$(qm status 106)" = 'status: stopped'
        if qm config 106 --snapshot aiw-vm106-baseline-20261021 >/dev/null 2>&1; then
            printf '%s\n' 'Baseline already exists; refusing to replace or adopt it' >&2
            exit 65
        fi
        qm snapshot 106 aiw-vm106-baseline-20261021 --vmstate 0
        ;;
    rollback)
        test "$(qm status 106)" = 'status: stopped'
        snapshot_config=$(qm config 106 --snapshot aiw-vm106-baseline-20261021)
        verify_config "$snapshot_config"
        if printf '%s\n' "$snapshot_config" | grep -E '^vmstate:' >/dev/null; then
            printf '%s\n' 'Memory-state snapshot is outside this boundary' >&2
            exit 65
        fi
        qm rollback 106 aiw-vm106-baseline-20261021
        ;;
    *) exit 64 ;;
esac
