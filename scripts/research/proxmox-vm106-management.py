#!/usr/bin/python3
"""Closed QGA bootstrap: firewall guard, fixed NIC link-up, HTTPS binding.

Caller supplies only Bootstrap or Info. Guest code is a fixed hash-bound payload;
credentials are never accepted or returned. Ambiguous guest dispatch is not retried.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/var/lib/aiw-vm106')
PAYLOAD = Path('/usr/local/libexec/aiw-vm106-management.ps1')
PAYLOAD_HASH = '9a1db78000dade58ef1173eddcdead5a7da487f6a3b9a2c3f8c5f912a424da98'
OFFLINE_NET = 'virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=1'
MANAGEMENT_NET = 'virtio=CC:34:21:7E:FE:59,bridge=vmbr0,link_down=0'


def save(path, record):
    with path.with_suffix('.tmp').open('x', encoding='utf-8') as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path.with_suffix('.tmp'), path)
    descriptor = os.open(str(ROOT), os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def qm(arguments, input_text=None, json_output=True):
    options = {'stdin': subprocess.DEVNULL} if input_text is None else {'input': input_text}
    result = subprocess.run(['/usr/sbin/qm', *arguments], check=True, capture_output=True,
                            text=True, timeout=35, close_fds=True, **options)
    return json.loads(result.stdout) if json_output else result.stdout


def guest(operation):
    path = ROOT / ('management-' + operation.lower() + '.json')
    if path.exists():
        record = json.loads(path.read_text())
        if record['payload'] != PAYLOAD_HASH or record['operation'] != operation:
            raise RuntimeError('Guest journal identity mismatch')
        if operation == 'Info' and record['phase'] == 'finished':
            path.rename(path.with_name('management-info-' + str(time.time_ns()) + '.json'))
    if not path.exists():
        record = {'phase': 'launch-intent', 'operation': operation, 'started': time.time(), 'payload': PAYLOAD_HASH}
        save(path, record)
        command = '$text=[Console]::In.ReadToEnd(); & ([scriptblock]::Create($text)) -Operation ' + operation
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        result = qm(['guest', 'exec', '106', '--synchronous', '0', '--pass-stdin', '1', '--',
                     r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                    input_text=PAYLOAD.read_text(encoding='utf-8'))
        if type(result.get('pid')) is not int or result['pid'] <= 0:
            raise RuntimeError('No guest PID; launch intent retained')
        record.update(phase='running', pid=result['pid'])
        save(path, record)
        return record
    if record['phase'] in ('launch-intent', 'collecting'):
        raise RuntimeError('Ambiguous guest operation; do not repeat or delete journal')
    if record['phase'] == 'running':
        record['phase'] = 'collecting'
        save(path, record)
        result = qm(['guest', 'exec-status', '106', str(record['pid'])])
        if result.get('exited') == 1:
            record.update(phase='finished', result=result)
        else:
            record['phase'] = 'running'
        save(path, record)
        if record['phase'] == 'finished':
            # Ephemeral proof: this call just collected completion. It is never
            # persisted, so a cached Guard cannot authorize a later activation.
            record['freshly_collected'] = True
    if record['phase'] == 'finished':
        result = record['result']
        if result.get('exitcode') != 0 or result.get('out-truncated') or result.get('err-truncated'):
            print(json.dumps(record))
            raise RuntimeError('Guest operation failed; evidence retained')
    elif time.time() - record['started'] > 180:
        print(json.dumps(record))
        raise RuntimeError('Guest deadline exceeded; no forced termination or retry')
    return record


def enable_network(guard_record):
    observed = json.loads(guard_record['result']['out-data'])
    if (observed.get('Phase') != 'Guarded' or observed.get('Result') != 'firewallGuardedBeforeNetwork'
            or observed.get('VmUuid', '').lower() != '7e686bee-8c05-43c7-9603-a9562ece224c'
            or observed.get('Controller') != '192.168.1.165'
            or observed.get('AdminSid') != 'S-1-5-21-3849540285-1795134874-2442050430-1006'):
        raise RuntimeError('Network guard receipt not verified')
    path = ROOT / 'management-network.json'
    if not path.exists():
        if guard_record.get('freshly_collected') is not True:
            raise RuntimeError('Fresh guard completion required for one-time NIC activation')
        save(path, {'phase': 'intent', 'payload': PAYLOAD_HASH, 'started': time.time()})
        new_intent = True
    else:
        new_intent = False
    network = json.loads(path.read_text())
    if network.get('payload') != PAYLOAD_HASH:
        raise RuntimeError('Network intent identity mismatch')
    config = qm(['config', '106', '--current', '1'], json_output=False).splitlines()
    if 'net0: ' + OFFLINE_NET in config:
        if not new_intent:
            raise RuntimeError('NIC disconnected or activation outcome uncertain; refusing cached reconnection')
        qm(['set', '106', '--net0', MANAGEMENT_NET], json_output=False)
    elif 'net0: ' + MANAGEMENT_NET not in config:
        raise RuntimeError('Unexpected network configuration')
    config = qm(['config', '106', '--current', '1'], json_output=False).splitlines()
    if 'net0: ' + MANAGEMENT_NET not in config:
        raise RuntimeError('NIC activation not confirmed; intent retained')
    network['phase'] = 'enabled'
    save(path, network)


def main():
    if os.getuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('Bootstrap', 'Info'):
        raise RuntimeError('Root and exact management operation required')
    if hashlib.sha256(PAYLOAD.read_bytes()).hexdigest() != PAYLOAD_HASH:
        raise RuntimeError('Management payload hash mismatch')
    if sys.argv[1] == 'Info':
        print(json.dumps(guest('Info')))
        return
    guard = guest('Guard')
    if guard['phase'] != 'finished':
        print(json.dumps(guard))
        return
    enable_network(guard)
    print(json.dumps(guest('Bind')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
