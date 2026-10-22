#!/bin/sh
# Credential-free dispatch/identity tests. Never calls a real Proxmox command.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d "$repo/.aiw-vm106-tests.XXXXXX")
case "$work" in "$repo"/.aiw-vm106-tests.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir "$work/bin"
export AIW_TEST_ROOT="$work"
# Rewrite only the fixed executable search path and root-owned runtime path in a
# disposable copy, so mocks cannot influence the production controller.
sed -e "s|^PATH=/usr/sbin:/usr/bin:/sbin:/bin$|PATH=$work/bin:/usr/bin:/bin|" \
    -e "s|/run/aiw-vm106|$work/run|g" \
    -e "s|/usr/bin/python3|$work/bin/python3|g" \
    "$repo/scripts/research/proxmox-vm106.sh" > "$work/controller"
cat > "$work/config" <<'CONFIG'
agent: 1
name: passkeys-worker
onboot: 0
smbios1: uuid=7e686bee-8c05-43c7-9603-a9562ece224c
ef id placeholder
net0: virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1
scsi0: r630-fast2:vm-106-disk-1,discard=on,iothread=1,size=100G,ssd=1
tpmstate0: r630-fast2:vm-106-disk-2,size=4M,version=v2.0
CONFIG
sed 's|^ef id placeholder$|efidisk0: r630-fast2:vm-106-disk-0,efitype=4m,ms-cert=2023k,pre-enrolled-keys=1,size=4M|' "$work/config" > "$work/base"
cp "$work/base" "$work/config"
cp "$work/base" "$work/pending"
cp "$work/base" "$work/snapshot"
printf '%s\n' stopped > "$work/state"
printf '%s\n' absent > "$work/snapshot-state"
printf '%s\n' 0 > "$work/uid"
printf '%s\n' pve-r630 > "$work/hostname"
cat > "$work/bin/id" <<'MOCK'
#!/bin/sh
cat "$AIW_TEST_ROOT/uid"
MOCK
cat > "$work/bin/hostname" <<'MOCK'
#!/bin/sh
cat "$AIW_TEST_ROOT/hostname"
MOCK
cat > "$work/bin/flock" <<'MOCK'
#!/bin/sh
# Dispatch tests only: real flock exclusion needs Linux host validation.
test "$*" = '-x -w 10 9'
# The helper must still own an open lock descriptor during acquisition.
(: >&9) 2>/dev/null || exit 98
test ! -e "$AIW_TEST_ROOT/lock-busy"
MOCK
cat > "$work/bin/pvesm" <<'MOCK'
#!/bin/sh
if (: >&9) 2>/dev/null; then
    printf '%s\n' 'Lock descriptor leaked into storage child' >&2; exit 98
fi
test "$*" = 'status --storage r630-fast2'
MOCK
cat > "$work/bin/qm" <<'MOCK'
#!/bin/sh
set -eu
if (: >&9) 2>/dev/null; then
    printf '%s\n' 'Lock descriptor leaked into qm child' >&2; exit 98
fi
printf '%s\n' "$*" >> "$AIW_TEST_ROOT/calls"
case "$*" in
    'config 106 --current 1') cat "$AIW_TEST_ROOT/config" ;;
    'config 106') cat "$AIW_TEST_ROOT/pending" ;;
    'config 106 --snapshot aiw-vm106-baseline-20261021')
        test "$(cat "$AIW_TEST_ROOT/snapshot-state")" = present
        cat "$AIW_TEST_ROOT/snapshot" ;;
    'status 106') printf 'status: %s\n' "$(cat "$AIW_TEST_ROOT/state")" ;;
    'listsnapshot 106') printf '%s\n' current ;;
    'shutdown 106 --timeout 120'|'start 106'|'snapshot 106 aiw-vm106-baseline-20261021 --vmstate 0'|'rollback 106 aiw-vm106-baseline-20261021')
        printf '%s\n' "$*" >> "$AIW_TEST_ROOT/mutations" ;;
    'set 106 --net0 virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1') printf '%s\n' "$*" >> "$AIW_TEST_ROOT/mutations" ;;
    *) printf 'Unexpected mock command: %s\n' "$*" >&2; exit 99 ;;
esac
MOCK
cat > "$work/bin/python3" <<'MOCK'
#!/bin/sh
if (: >&9) 2>/dev/null; then exit 98; fi
case "$*" in
    '/usr/local/libexec/aiw-vm106-cleanup.py') operation=worker-cleanup ;;
    '/usr/local/libexec/aiw-vm106-prepare.py Prepare') operation=worker-prepare ;;
    '/usr/local/libexec/aiw-vm106-prepare.py Verify') operation=worker-verify ;;
    '/usr/local/libexec/aiw-vm106-prepare.py Finalize') operation=worker-finalize ;;
    '/usr/local/libexec/aiw-vm106-prepare.py State') operation=worker-preparation-state ;;
    '/usr/local/libexec/aiw-vm106-management.py Bootstrap') operation=worker-access ;;
    '/usr/local/libexec/aiw-vm106-management.py Info') operation=worker-access-info ;;
    *) exit 99 ;;
esac
printf '%s\n' "$operation" >> "$AIW_TEST_ROOT/mutations"
MOCK
chmod +x "$work/bin/"*
passed=0
run_pass() {
    verb=$1; expected=$2
    : > "$work/mutations"
    SSH_ORIGINAL_COMMAND="$verb" sh "$work/controller" > "$work/out" 2>&1 || {
        cat "$work/out" >&2; printf 'Expected success: %s\n' "$verb" >&2; exit 1;
    }
    actual=$(cat "$work/mutations")
    test "$actual" = "$expected" || { printf 'Wrong dispatch: %s\n' "$verb" >&2; exit 1; }
    passed=$((passed + 1))
}
run_reject() {
    verb=$1; shift
    : > "$work/mutations"
    if SSH_ORIGINAL_COMMAND="$verb" sh "$work/controller" "$@" > "$work/out" 2>&1; then
        printf 'Expected rejection: %s\n' "$verb" >&2; exit 1
    fi
    test ! -s "$work/mutations" || { printf 'Mutation after rejection\n' >&2; exit 1; }
    passed=$((passed + 1))
}
run_pass inspect ''
run_pass status ''
run_reject worker-cleanup
printf '%s\n' running > "$work/state"
run_pass worker-cleanup worker-cleanup
run_pass worker-prepare worker-prepare
run_pass worker-verify worker-verify
run_pass worker-finalize worker-finalize
run_pass worker-preparation-state worker-preparation-state
run_pass worker-access worker-access
run_pass worker-access-info worker-access-info
run_pass worker-disconnect 'set 106 --net0 virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1'
run_reject 'worker-prepare other'
run_reject 'worker-verify; whoami'
run_reject 'worker-access arbitrary-code'
# Both exact link states preserve identity; other bridges and MACs are rejected.
sed 's/link_down=1/link_down=0/' "$work/base" > "$work/config"
cp "$work/config" "$work/pending"
run_pass inspect ''
sed 's/bridge=vmbr0/bridge=vmbr9/' "$work/config" > "$work/changed"
cp "$work/changed" "$work/config"
cp "$work/config" "$work/pending"
run_reject inspect
cp "$work/base" "$work/config"
cp "$work/base" "$work/pending"
printf '%s\n' stopped > "$work/state"
touch "$work/lock-busy"
run_reject start
grep -Fx 'VM 106 helper lock is busy; no operation performed' "$work/out" >/dev/null
rm "$work/lock-busy"
run_pass start 'start 106'
run_pass shutdown 'shutdown 106 --timeout 120'
run_pass snapshot 'snapshot 106 aiw-vm106-baseline-20261021 --vmstate 0'
printf '%s\n' present > "$work/snapshot-state"
run_pass rollback 'rollback 106 aiw-vm106-baseline-20261021'
run_reject snapshot
run_reject ''
run_reject 'inspect; start 203'
run_reject 'start 203'
run_reject inspect unexpected-argument
printf '%s\n' 1000 > "$work/uid"
run_reject start
printf '%s\n' 0 > "$work/uid"
printf '%s\n' wrong-host > "$work/hostname"
run_reject start
printf '%s\n' pve-r630 > "$work/hostname"
printf '%s\n' 'memory: 999' >> "$work/pending"
run_reject start
cp "$work/base" "$work/pending"
# Every independently observed identity/storage/network field must be required.
for field in name smbios1 efidisk0 scsi0 tpmstate0 net0 onboot agent; do
    sed "/^$field:/d" "$work/base" > "$work/config"
    cp "$work/config" "$work/pending"
    run_reject start
done
cp "$work/base" "$work/config"
printf '%s\n' 'net1: virtio=00:11:22:33:44:55,bridge=vmbr0' >> "$work/config"
cp "$work/config" "$work/pending"
run_reject start
cp "$work/base" "$work/config"
cp "$work/base" "$work/pending"
printf '%s\n' running > "$work/state"
run_reject snapshot
run_reject rollback
printf '%s\n' stopped > "$work/state"
sed '/^smbios1:/d' "$work/base" > "$work/snapshot"
run_reject rollback
cp "$work/base" "$work/snapshot"
printf '%s\n' 'vmstate: r630-fast2:unexpected-state' >> "$work/snapshot"
run_reject rollback
# Config additions must fail in current state and in the rollback target.
for extra in \
    'args: -netdev user,id=extra -device e1000,netdev=extra' \
    'hostpci0: 0000:01:00.0' \
    'usb0: host=1234:5678' \
    'hookscript: local:snippets/unreviewed.pl'; do
    cp "$work/base" "$work/config"
    printf '%s\n' "$extra" >> "$work/config"
    cp "$work/config" "$work/pending"
    run_reject start
    cp "$work/base" "$work/config"
    cp "$work/base" "$work/pending"
    cp "$work/base" "$work/snapshot"
    printf '%s\n' "$extra" >> "$work/snapshot"
    run_reject rollback
done
cp "$work/base" "$work/snapshot"
printf '%s\n' absent > "$work/snapshot-state"
run_reject rollback
printf 'Passed %s VM 106 dispatch and identity checks; no VM operations executed.\n' "$passed"
