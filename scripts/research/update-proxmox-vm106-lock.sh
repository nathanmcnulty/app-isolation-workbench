#!/bin/sh
# One-time recovery of the reviewed first version; no key or lock-file deletion.
set -eu
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
test -f /usr/local/sbin/aiw-vm106
test ! -L /usr/local/sbin/aiw-vm106
expected_old=7a6454f5478f2a89cfa034e962818a39e8d0a50db80cbb28acfff9ea0c1c006c
test "$(sha256sum /usr/local/sbin/aiw-vm106 | cut -d ' ' -f 1)" = "$expected_old"
file=$(mktemp /tmp/aiw-vm106-lockfix.XXXXXX)
replacement=''
cleanup() {
    rm -f -- "$file"
    if test -n "$replacement"; then rm -f -- "$replacement"; fi
}
trap cleanup EXIT HUP INT TERM
curl -fsSL 'https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/184022c052db84e2a31a9eeee7defdfd07066a35/scripts/research/proxmox-vm106.sh' -o "$file"
printf '%s  %s\n' 'd51cec1cca050118063758a09a43fd8af7e36cac8834e4775fc1273bd3326955' "$file" | sha256sum -c -
sh -n "$file"
# Check the exact target before the graceful shutdown that releases inherited FDs.
config=$(qm config 106 --current 1)
test "$config" = "$(qm config 106)"
for expected in \
    'name: passkeys-worker' \
    'smbios1: uuid=7e686bee-8c05-43c7-9603-a9562ece224c' \
    'net0: virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1'; do
    printf '%s\n' "$config" | grep -Fx "$expected" >/dev/null
done
case "$(qm status 106)" in
    'status: running') qm shutdown 106 --timeout 120 ;;
    'status: stopped') ;;
    *) printf '%s\n' 'Unexpected VM state; recovery stopped' >&2; exit 65 ;;
esac
test "$(qm status 106)" = 'status: stopped'
# Revalidate every pinned field through the new helper. A remaining lock fails
# here without killing a process, deleting the lock, or replacing any code.
SSH_ORIGINAL_COMMAND=inspect sh "$file"
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9
test "$(qm status 106 9>&-)" = 'status: stopped'
test "$(sha256sum /usr/local/sbin/aiw-vm106 9>&- | cut -d ' ' -f 1)" = "$expected_old"
replacement=$(mktemp /usr/local/sbin/.aiw-vm106.XXXXXX)
install -o root -g root -m 755 "$file" "$replacement" 9>&-
mv -fT -- "$replacement" /usr/local/sbin/aiw-vm106 9>&-
replacement=''
flock -u 9
exec 9>&-
SSH_ORIGINAL_COMMAND=inspect /usr/local/sbin/aiw-vm106
printf '%s\n' 'VM 106 lock fix installed; existing SSH key preserved; worker stopped and disconnected.'
sha256sum /usr/local/sbin/aiw-vm106
