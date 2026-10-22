#!/bin/sh
# Adds only fixed offline preparation operations. No guest setup is launched here.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
old=beb5652a928a06be69c167fc68073a5147af6f0e769db9ee47c0a2233bd507be
test -f /usr/local/sbin/aiw-vm106
test ! -L /usr/local/sbin/aiw-vm106
test "$(sha256sum /usr/local/sbin/aiw-vm106 | cut -d ' ' -f 1)" = "$old"
work=$(mktemp -d /tmp/aiw-vm106-preparation.XXXXXX)
replacement=''
cleanup() {
    rm -f -- "$work/helper" "$work/runner" "$work/payload"
    rmdir -- "$work"
    if test -n "$replacement"; then rm -f -- "$replacement"; fi
}
trap cleanup EXIT HUP INT TERM
base=https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/4d80297b349fcf7aed0761bd307f3d1464bacb13/scripts/research
curl -fsSL "$base/proxmox-vm106.sh" -o "$work/helper"
curl -fsSL "$base/proxmox-vm106-prepare.py" -o "$work/runner"
curl -fsSL "$base/Prepare-Worker106Offline.ps1" -o "$work/payload"
printf '%s  %s\n' \
    64651fd9ff51368a858f700c7387c25d0525d4f7c4dc9f22fc36028cc4c844a0 "$work/helper" \
    e7496b85832ab7921aba62843c7eafcf1b04b7af90ae84b307aa7e1f5a0cb739 "$work/runner" \
    c4ea40b8393c17e41aaa3589ad0c3c45b28a640ba897d13bafe258b769793f05 "$work/payload" | sha256sum -c -
sh -n "$work/helper"
/usr/bin/python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$work/runner"
SSH_ORIGINAL_COMMAND=inspect sh "$work/helper"
timeout 30 qm guest cmd 106 ping
for directory in /usr/local /usr/local/sbin /usr/local/libexec /var/lib /var/lib/aiw-vm106; do
    test -d "$directory"
    test ! -L "$directory"
    test "$(stat -c %u "$directory")" = 0
    mode=$(stat -c %a "$directory")
    test "$((0$mode & 022))" = 0
done
test "$(stat -c %a /var/lib/aiw-vm106)" = 700
test -f /var/lib/aiw-vm106/cleanup.json
test ! -L /var/lib/aiw-vm106/cleanup.json
/usr/bin/python3 -c 'import json; r=json.load(open("/var/lib/aiw-vm106/cleanup.json")); assert r["payload"] == "400142b0b0a49fb22c3235c6b845511905006b76392fa2b59530e2dd8f2766f1" and r["phase"] == "finished" and r["result"]["exitcode"] == 0'
for target in /usr/local/libexec/aiw-vm106-prepare.py /usr/local/libexec/aiw-vm106-prepare.ps1 /var/lib/aiw-vm106/prepare.json /var/lib/aiw-vm106/verify.json /var/lib/aiw-vm106/finalize.json /var/lib/aiw-vm106/state.json; do
    test ! -e "$target"
    test ! -L "$target"
done
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9
test "$(sha256sum /usr/local/sbin/aiw-vm106 9>&- | cut -d ' ' -f 1)" = "$old"
install -o root -g root -m 600 "$work/payload" /usr/local/libexec/aiw-vm106-prepare.ps1 9>&-
install -o root -g root -m 600 "$work/runner" /usr/local/libexec/aiw-vm106-prepare.py 9>&-
replacement=$(mktemp /usr/local/sbin/.aiw-vm106.XXXXXX)
install -o root -g root -m 755 "$work/helper" "$replacement" 9>&-
mv -fT -- "$replacement" /usr/local/sbin/aiw-vm106 9>&-
replacement=''
flock -u 9
exec 9>&-
SSH_ORIGINAL_COMMAND=inspect /usr/local/sbin/aiw-vm106
printf '%s\n' 'VM 106 offline preparation operations installed; no guest setup launched.'
sha256sum /usr/local/sbin/aiw-vm106
