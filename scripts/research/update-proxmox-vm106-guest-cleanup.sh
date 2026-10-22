#!/bin/sh
# One host-side update. Does not launch a guest process or alter SSH keys.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
old=d51cec1cca050118063758a09a43fd8af7e36cac8834e4775fc1273bd3326955
test -f /usr/local/sbin/aiw-vm106
test ! -L /usr/local/sbin/aiw-vm106
test "$(sha256sum /usr/local/sbin/aiw-vm106 | cut -d ' ' -f 1)" = "$old"
work=$(mktemp -d /tmp/aiw-vm106-guest.XXXXXX)
replacement=''
cleanup() {
    rm -f -- "$work/helper" "$work/runner" "$work/payload"
    rmdir -- "$work"
    if test -n "$replacement"; then rm -f -- "$replacement"; fi
}
trap cleanup EXIT HUP INT TERM
base=https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/48038f402f8d16b78ac65229eccdc606cd94aa87/scripts/research
curl -fsSL "$base/proxmox-vm106.sh" -o "$work/helper"
curl -fsSL "$base/proxmox-vm106-cleanup.py" -o "$work/runner"
curl -fsSL "$base/Complete-Worker106TailscaleCleanup.ps1" -o "$work/payload"
printf '%s  %s\n' \
    beb5652a928a06be69c167fc68073a5147af6f0e769db9ee47c0a2233bd507be "$work/helper" \
    86619184b63177df232f078607e8c70ccfc879dd8a1e800b3d8b55210ccc75af "$work/runner" \
    400142b0b0a49fb22c3235c6b845511905006b76392fa2b59530e2dd8f2766f1 "$work/payload" | sha256sum -c -
sh -n "$work/helper"
/usr/bin/python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$work/runner"
# This checks every VM pin through the new helper without executing guest code.
SSH_ORIGINAL_COMMAND=inspect sh "$work/helper"
# Require a responsive guest agent before changing the installed helper.
qm guest cmd 106 ping
for directory in /usr/local /usr/local/sbin /var/lib; do
    test -d "$directory"
    test ! -L "$directory"
    test "$(stat -c %u "$directory")" = 0
    mode=$(stat -c %a "$directory")
    test "$((0$mode & 022))" = 0
done
if test ! -e /usr/local/libexec; then install -d -o root -g root -m 755 /usr/local/libexec; fi
test -d /usr/local/libexec
test ! -L /usr/local/libexec
test "$(stat -c %u /usr/local/libexec)" = 0
mode=$(stat -c %a /usr/local/libexec)
test "$((0$mode & 022))" = 0
for target in /usr/local/libexec/aiw-vm106-cleanup.py /usr/local/libexec/aiw-vm106-cleanup.ps1 /var/lib/aiw-vm106; do
    test ! -e "$target"
    test ! -L "$target"
done
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9
test "$(sha256sum /usr/local/sbin/aiw-vm106 9>&- | cut -d ' ' -f 1)" = "$old"
# Root-only journal directory; its state must not be removed to retry a run.
install -d -o root -g root -m 700 /var/lib/aiw-vm106 9>&-
install -o root -g root -m 600 "$work/payload" /usr/local/libexec/aiw-vm106-cleanup.ps1 9>&-
install -o root -g root -m 600 "$work/runner" /usr/local/libexec/aiw-vm106-cleanup.py 9>&-
replacement=$(mktemp /usr/local/sbin/.aiw-vm106.XXXXXX)
install -o root -g root -m 755 "$work/helper" "$replacement" 9>&-
mv -fT -- "$replacement" /usr/local/sbin/aiw-vm106 9>&-
replacement=''
flock -u 9
exec 9>&-
SSH_ORIGINAL_COMMAND=inspect /usr/local/sbin/aiw-vm106
printf '%s\n' 'Fixed VM 106 guest cleanup installed; guest agent responds; no guest operation launched.'
sha256sum /usr/local/sbin/aiw-vm106
