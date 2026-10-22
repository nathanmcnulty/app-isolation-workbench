#!/bin/sh
# Fixed one-time management bootstrap; the operator requested remote access.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
test "$(id -u)" = 0
test "$(hostname -s)" = pve-r630
test "$#" = 0
old=64651fd9ff51368a858f700c7387c25d0525d4f7c4dc9f22fc36028cc4c844a0
for directory in /usr/local /usr/local/sbin /usr/local/libexec /var/lib /var/lib/aiw-vm106; do
    test -d "$directory"
    test ! -L "$directory"
    test "$(stat -c %u "$directory")" = 0
    mode=$(stat -c %a "$directory")
    test "$((0$mode & 022))" = 0
done
test "$(stat -c %a /var/lib/aiw-vm106)" = 700
test -f /usr/local/sbin/aiw-vm106
test ! -L /usr/local/sbin/aiw-vm106
test "$(sha256sum /usr/local/sbin/aiw-vm106 | cut -d ' ' -f 1)" = "$old"
work=$(mktemp -d /tmp/aiw-vm106-management.XXXXXX)
replacement=''
cleanup() {
    rm -f -- "$work/helper" "$work/runner" "$work/payload"
    rmdir -- "$work"
    if test -n "$replacement"; then rm -f -- "$replacement"; fi
}
trap cleanup EXIT HUP INT TERM
base=https://raw.githubusercontent.com/nathanmcnulty/app-isolation-workbench/a579d6907ca9bc6b7961e1fa6503a2ef67936e47/scripts/research
curl -fsSL "$base/proxmox-vm106.sh" -o "$work/helper"
curl -fsSL "$base/proxmox-vm106-management.py" -o "$work/runner"
curl -fsSL "$base/Enable-Worker106Management.ps1" -o "$work/payload"
printf '%s  %s\n' \
    e964245d88171c408b0a82afea6760f6c81c614e082a51c94e89cdeca842bfef "$work/helper" \
    7cad96afdfce0b23236304cb1efc1fb042fdd12fe1bcd1d0f2cc1d545d0487c9 "$work/runner" \
    70030f37f84de9b45c1aeecf1917bd470d406c7eafca771b800d33d45266213a "$work/payload" | sha256sum -c -
sh -n "$work/helper"
/usr/bin/python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$work/runner"
SSH_ORIGINAL_COMMAND=inspect /usr/local/sbin/aiw-vm106
timeout 30 qm guest cmd 106 ping
exec 9>/run/aiw-vm106/lock
flock -x -w 10 9
test "$(sha256sum /usr/local/sbin/aiw-vm106 9>&- | cut -d ' ' -f 1)" = "$old"
qm config 106 --current 1 9>&- | grep -Fx 'net0: virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1' >/dev/null
for target in /usr/local/libexec/aiw-vm106-management.py /usr/local/libexec/aiw-vm106-management.ps1 /var/lib/aiw-vm106/management-guard.json /var/lib/aiw-vm106/management-bind.json /var/lib/aiw-vm106/management-network.json /var/lib/aiw-vm106/management-info.json; do
    test ! -e "$target"
    test ! -L "$target"
done
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
assert (root/"prepare.json").is_file()
' 9>&-
install -o root -g root -m 600 "$work/payload" /usr/local/libexec/aiw-vm106-management.ps1 9>&-
install -o root -g root -m 600 "$work/runner" /usr/local/libexec/aiw-vm106-management.py 9>&-
replacement=$(mktemp /usr/local/sbin/.aiw-vm106.XXXXXX)
install -o root -g root -m 755 "$work/helper" "$replacement" 9>&-
mv -fT -- "$replacement" /usr/local/sbin/aiw-vm106 9>&-
replacement=''
flock -u 9
exec 9>&-
printf '%s\n' 'Management helper installed; launching fixed firewall guard. Controller will finish and verify HTTPS access.'
# Complete the fixed bootstrap without another Windows or host paste. Each call
# resumes recorded custody, never repeats an ambiguously launched guest process.
deadline=$(($(date +%s) + 240))
ready=0
while test "$(date +%s)" -lt "$deadline"; do
    result=$(SSH_ORIGINAL_COMMAND=worker-access /usr/local/sbin/aiw-vm106)
    printf '%s\n' "$result"
    if printf '%s\n' "$result" | /usr/bin/python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if r.get("operation") == "Bind" and r.get("phase") == "finished" and r["result"]["exitcode"] == 0 else 1)'; then
        ready=1
        break
    fi
    sleep 2
done
test "$ready" = 1 || { printf '%s\n' 'Bootstrap deadline reached; preserve journals, do not reinstall' >&2; exit 1; }
printf '%s\n' 'VM 106 HTTPS management configured. Codex can now verify remote access from the controller.'
sha256sum /usr/local/sbin/aiw-vm106
