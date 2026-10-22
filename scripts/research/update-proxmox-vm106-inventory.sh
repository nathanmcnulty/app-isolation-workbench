#!/bin/sh
# Correct only the fixed PowerShell inventory layout; preserve completed setup.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
for directory in /usr/local /usr/local/sbin /usr/local/libexec /var/lib /var/lib/aiw-vm106; do
    test -d "$directory"
    test ! -L "$directory"
    test "$(stat -c %u "$directory")" = 0
    mode=$(stat -c %a "$directory")
    test "$((0$mode & 022))" = 0
done
for target in /usr/local/sbin/aiw-vm106 /usr/local/libexec/aiw-vm106-prepare.py /usr/local/libexec/aiw-vm106-prepare.ps1; do
    test -f "$target"
    test ! -L "$target"
    test "$(stat -c %u "$target")" = 0
done
work=$(mktemp -d /tmp/aiw-vm106-inventory.XXXXXX)
payload_replacement=''; runner_replacement=''
cleanup() {
    rm -f -- "$work/payload" "$work/runner"
    rmdir -- "$work"
    if test -n "$payload_replacement"; then rm -f -- "$payload_replacement"; fi
    if test -n "$runner_replacement"; then rm -f -- "$runner_replacement"; fi
}
trap cleanup EXIT HUP INT TERM
base=https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/dcef8bef278951514dbdbf278ddb053f8e51ac4f/scripts/research
curl -fsSL "$base/Prepare-Worker106Offline.ps1" -o "$work/payload"
curl -fsSL "$base/proxmox-vm106-prepare.py" -o "$work/runner"
printf '%s  %s\n' \
    fb561897488440a1cb89859f988e3e4e2e807e7ab4832d4b2cc53b8d60700182 "$work/payload" \
    ac547718637d6518c7acef468c1e5daf9e473660d137941a144e0dd22e937755 "$work/runner" | sha256sum -c -
/usr/bin/python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$work/runner"
printf '%s  %s\n' 64651fd9ff51368a858f700c7387c25d0525d4f7c4dc9f22fc36028cc4c844a0 /usr/local/sbin/aiw-vm106 | sha256sum -c -
SSH_ORIGINAL_COMMAND=inspect /usr/local/sbin/aiw-vm106
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9
printf '%s  %s\n' \
    64651fd9ff51368a858f700c7387c25d0525d4f7c4dc9f22fc36028cc4c844a0 /usr/local/sbin/aiw-vm106 \
    c4ea40b8393c17e41aaa3589ad0c3c45b28a640ba897d13bafe258b769793f05 /usr/local/libexec/aiw-vm106-prepare.ps1 \
    e7496b85832ab7921aba62843c7eafcf1b04b7af90ae84b307aa7e1f5a0cb739 /usr/local/libexec/aiw-vm106-prepare.py | sha256sum -c - 9>&-
# Never change a payload while a helper-launched guest process may still use it.
/usr/bin/python3 -c '
import json, pathlib
root=pathlib.Path("/var/lib/aiw-vm106")
for operation in ("prepare", "verify", "state", "finalize"):
    path=root/(operation+".json")
    if path.exists():
        assert not path.is_symlink()
        record=json.loads(path.read_text())
        assert record["phase"] == "finished", "Unfinished guest operation; preserve state"
        if operation == "prepare": assert record["result"]["exitcode"] == 0
assert (root/"prepare.json").is_file() and (root/"verify.json").is_file()
' 9>&-
payload_replacement=$(mktemp /usr/local/libexec/.aiw-vm106-payload.XXXXXX)
runner_replacement=$(mktemp /usr/local/libexec/.aiw-vm106-runner.XXXXXX)
install -o root -g root -m 600 "$work/payload" "$payload_replacement" 9>&-
install -o root -g root -m 600 "$work/runner" "$runner_replacement" 9>&-
mv -fT -- "$payload_replacement" /usr/local/libexec/aiw-vm106-prepare.ps1 9>&-
payload_replacement=''
mv -fT -- "$runner_replacement" /usr/local/libexec/aiw-vm106-prepare.py 9>&-
runner_replacement=''
flock -u 9
exec 9>&-
printf '%s\n' 'VM 106 inventory correction installed; existing accounts, credentials and journals preserved.'
sha256sum /usr/local/libexec/aiw-vm106-prepare.ps1 /usr/local/libexec/aiw-vm106-prepare.py
