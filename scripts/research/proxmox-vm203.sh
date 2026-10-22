#!/bin/sh
# Fixed research boundary for the dedicated AIW VM; installed root-owned.
# No arguments, shell text, VM IDs or snapshot names are accepted from callers.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect|status|shutdown|start|snapshot|rollback) ;;
    *) printf '%s\n' 'Unsupported AIW operation' >&2; exit 64 ;;
esac
# /run is root-controlled. Serialize checks and operations across this key's calls.
umask 077
mkdir -p /run/aiw-vm203
exec 9>/run/aiw-vm203/lock
flock -x -w 10 9
config=$(qm config 203 --current 1)
# Reject pending changes before acting on either the live or next-boot identity.
test "$config" = "$(qm config 203)"
printf '%s\n' "$config" | grep -Fx 'name: aiw' >/dev/null
printf '%s\n' "$config" | grep -Fx 'smbios1: uuid=652a575b-a462-418e-95bb-360b28516925' >/dev/null
case "${SSH_ORIGINAL_COMMAND-}" in
    inspect)
        printf '%s\n' "$config"
        qm status 203
        qm listsnapshot 203
        pvesm status --storage r630-bulk
        ;;
    status) qm status 203 ;;
    shutdown) qm shutdown 203 --timeout 120 ;;
    start) qm start 203 ;;
    snapshot)
        test "$(qm status 203)" = 'status: stopped'
        qm snapshot 203 aiw-msix-baseline-20261021 --vmstate 0
        ;;
    rollback)
        test "$(qm status 203)" = 'status: stopped'
        qm rollback 203 aiw-msix-baseline-20261021
        ;;
    *) printf '%s\n' 'Unsupported AIW operation' >&2; exit 64 ;;
esac
