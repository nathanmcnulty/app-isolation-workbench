#!/bin/sh
# Run once in the Proxmox root shell. Installs a fixed forced command.
set -eu
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test ! -e /usr/local/sbin/aiw-vm106
test ! -L /usr/local/sbin/aiw-vm106
test ! -L /root/.ssh
file=$(mktemp /tmp/aiw-vm106.XXXXXX)
trap 'rm -f -- "$file"' EXIT HUP INT TERM
curl -fsSL 'https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/61a531708633cda4dad9708e5ff1af887072d541/scripts/research/proxmox-vm106.sh' -o "$file"
printf '%s  %s\n' '7a6454f5478f2a89cfa034e962818a39e8d0a50db80cbb28acfff9ea0c1c006c' "$file" | sha256sum -c -
sh -n "$file"
test "$(qm status 106)" = 'status: stopped'
# Read-only identity, pending-config, isolation and storage inspection.
SSH_ORIGINAL_COMMAND=inspect sh "$file"
mkdir -p /root/.ssh
chmod 700 /root/.ssh
chown root:root /root/.ssh
authorized_keys=/root/.ssh/authorized_keys
if test -L "$authorized_keys"; then
    # Proxmox normally links root keys into its cluster-managed private filesystem.
    test "$(readlink -f -- "$authorized_keys")" = /etc/pve/priv/authorized_keys
    authorized_keys=/etc/pve/priv/authorized_keys
    test -f "$authorized_keys"
    test "$(stat -Lc %u "$authorized_keys")" = 0
    test "$(stat -Lc %a "$authorized_keys")" = 600
else
    if test -e "$authorized_keys"; then test -f "$authorized_keys"; fi
    touch "$authorized_keys"
    chown root:root "$authorized_keys"
    chmod 600 "$authorized_keys"
fi
install -o root -g root -m 755 "$file" /usr/local/sbin/aiw-vm106
keyline='restrict,command="/usr/local/sbin/aiw-vm106" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2jg2q6fhVbjrddXedLeVsbQHlyVlidqKtNETaZetg2 aiw-codex-vm106-20261021'
if ! grep -Fx -- "$keyline" "$authorized_keys" >/dev/null; then
    printf '\n%s\n' "$keyline" >> "$authorized_keys"
fi
printf '%s\n' 'Installed restricted VM 106 helper; worker remains stopped and disconnected.'
sha256sum /usr/local/sbin/aiw-vm106
