#!/bin/sh
# Closed management for offline AIW worker 107, never development VM 203.
# Install root-owned at the existing forced-command entry path to retire 203 access.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect|status|guest-info|shutdown|start|snapshot|rollback) ;;
    *) printf '%s\n' 'Unsupported AIW operation' >&2; exit 64 ;;
esac
umask 077
mkdir -p /run/aiw-worker107
exec 9>/run/aiw-worker107/lock
flock -x -w 10 9
require_worker_identity() {
    printf '%s\n' "$1" | grep -Fx 'name: aiw-worker' >/dev/null
    printf '%s\n' "$1" | grep -Fx 'smbios1: uuid=e5cecc90-35c2-4831-bf9c-424be23f7d4e' >/dev/null
    printf '%s\n' "$1" | grep -Fx 'net0: virtio=CC:34:21:B8:5A:31,bridge=vmbr0,link_down=1' >/dev/null
    printf '%s\n' "$1" | grep -Fx 'scsi0: r630-fast:vm-107-disk-1,discard=on,iothread=1,size=100G,ssd=1' >/dev/null
    printf '%s\n' "$1" | grep -Fx 'efidisk0: r630-fast:vm-107-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M' >/dev/null
    printf '%s\n' "$1" | grep -Fx 'tpmstate0: r630-fast:vm-107-disk-2,size=4M,version=v2.0' >/dev/null
    # Only observed config keys and disk-only snapshot metadata are accepted.
    # Unknown attachments (including ivshmem, serial and parallel) fail closed.
    if printf '%s\n' "$1" | sed 's/:.*//' | grep -Ev '^(agent|balloon|bios|boot|cores|cpu|description|efidisk0|ide2|machine|memory|meta|name|net0|numa|onboot|ostype|scsi0|scsihw|smbios1|sockets|tags|tpmstate0|vga|vmgenid|snaptime|parent)$' >/dev/null; then
        printf '%s\n' 'Unexpected worker configuration key' >&2
        return 1
    fi
    printf '%s\n' "$1" | grep -Fx 'ide2: none,media=cdrom' >/dev/null
}
config=$(qm config 107 --current 1)
test "$config" = "$(qm config 107)"
require_worker_identity "$config"
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect)
        printf '%s\n' "$config"
        qm status 107
        qm listsnapshot 107
        pvesm status --storage r630-fast
        ;;
    status) qm status 107 ;;
    guest-info)
        test "$(qm status 107)" = 'status: running'
        qm guest cmd 107 ping
        qm guest cmd 107 get-osinfo
        qm guest cmd 107 get-host-name
        qm guest cmd 107 get-users
        ;;
    shutdown) qm shutdown 107 --timeout 120 ;;
    start) qm start 107 ;;
    snapshot)
        test "$(qm status 107)" = 'status: stopped'
        qm snapshot 107 aiw-msix-worker107-clean-r1 --vmstate 0
        ;;
    rollback)
        test "$(qm status 107)" = 'status: stopped'
        snapshot_config=$(qm config 107 --snapshot aiw-msix-worker107-clean-r1)
        require_worker_identity "$snapshot_config"
        qm rollback 107 aiw-msix-worker107-clean-r1
        ;;
esac
