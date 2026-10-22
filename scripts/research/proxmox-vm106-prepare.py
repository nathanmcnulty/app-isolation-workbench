#!/usr/bin/python3
"""Closed, journaled worker preparation operations; caller cannot supply code or a PID.

Invoked under the parent's flock after its complete VM config check. The journal
survives host reboot. Ambiguous launch/status failures are retained, never retried.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

PAYLOAD = Path('/usr/local/libexec/aiw-vm106-prepare.ps1')
PAYLOAD_HASH = 'c4ea40b8393c17e41aaa3589ad0c3c45b28a640ba897d13bafe258b769793f05'
STATE = None
STATE_ROOT = Path('/var/lib/aiw-vm106')


def save(record):
    temporary = STATE.with_suffix('.tmp')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(record, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, STATE)
    directory = os.open(str(STATE.parent), os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def qm(arguments, input_text=None):
    input_options = {'stdin': subprocess.DEVNULL} if input_text is None else {'input': input_text}
    result = subprocess.run(['/usr/sbin/qm', *arguments], check=True,
                            capture_output=True, text=True, timeout=35,
                            close_fds=True, **input_options)
    return json.loads(result.stdout)


def main():
    global STATE
    if len(sys.argv) != 2 or sys.argv[1] not in ('Prepare', 'Verify', 'Finalize', 'State') or os.getuid() != 0:
        raise RuntimeError('Root and exact fixed operation required')
    operation = sys.argv[1]
    STATE = STATE_ROOT / (operation.lower() + '.json')
    payload = PAYLOAD.read_bytes()
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_HASH:
        raise RuntimeError('Fixed payload hash mismatch')
    if STATE.exists():
        record = json.loads(STATE.read_text(encoding='utf-8'))
        if operation in ('Verify', 'State') and record['phase'] == 'finished':
            STATE.rename(STATE.with_name(operation.lower() + '-' + str(time.time_ns()) + '.json'))
    if not STATE.exists():
        record = {'phase': 'launch-intent', 'started': time.time(), 'payload': PAYLOAD_HASH}
        save(record)  # A crash from this point requires review, never redispatch.
        # A small fixed bootstrap avoids Windows' command-line length limit.
        # Only the hash-verified script goes through stdin; caller input is never read.
        command = "$text=[Console]::In.ReadToEnd(); & ([scriptblock]::Create($text)) -Operation " + operation
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        launch = qm(['guest', 'exec', '106', '--synchronous', '0', '--pass-stdin', '1', '--',
                     r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                     encoded], input_text=payload.decode('utf-8'))
        pid = launch.get('pid')
        if type(pid) is not int or pid <= 0:
            raise RuntimeError('No valid guest PID; launch state retained')
        record.update(phase='running', pid=pid)
        save(record)
    if record.get('payload') != PAYLOAD_HASH:
        raise RuntimeError('Journal belongs to a different payload')
    if record['phase'] == 'launch-intent':
        raise RuntimeError('Launch outcome unknown; refusing repeat')
    if record['phase'] == 'running':
        # Persist collection intent before the reaping guest-exec-status call.
        # A transport failure leaves this state for review, never a new launch.
        record['phase'] = 'collecting'
        save(record)
        result = qm(['guest', 'exec-status', '106', str(record['pid'])])
        if result.get('exited') is True or result.get('exited') == 1:
            record.update(phase='finished', result=result)
        else:
            record['phase'] = 'running'
        save(record)
    print(json.dumps(record))
    if record['phase'] == 'collecting':
        raise RuntimeError('Collection outcome unknown; preserve journal for review')
    if record['phase'] == 'finished':
        result = record['result']
        if result.get('exitcode') != 0 or result.get('out-truncated') or result.get('err-truncated'):
            raise RuntimeError('Guest operation failed or output truncated; evidence retained')
    elif time.time() - record['started'] > 120:
        raise RuntimeError('Guest operation exceeded 120 seconds; no repeat or forced termination')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
