#!/usr/bin/python3
"""One fixed, journaled guest operation; caller cannot supply code or a PID.

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

PAYLOAD = Path('/usr/local/libexec/aiw-vm106-cleanup.ps1')
PAYLOAD_HASH = '400142b0b0a49fb22c3235c6b845511905006b76392fa2b59530e2dd8f2766f1'
STATE = Path('/var/lib/aiw-vm106/cleanup.json')


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


def qm(arguments):
    result = subprocess.run(['/usr/sbin/qm', *arguments], check=True,
                            capture_output=True, text=True, timeout=35,
                            stdin=subprocess.DEVNULL, close_fds=True)
    return json.loads(result.stdout)


def main():
    if len(sys.argv) != 1 or os.getuid() != 0:
        raise RuntimeError('Root and no arguments required')
    payload = PAYLOAD.read_bytes()
    if hashlib.sha256(payload).hexdigest() != PAYLOAD_HASH:
        raise RuntimeError('Fixed payload hash mismatch')
    if STATE.exists():
        record = json.loads(STATE.read_text(encoding='utf-8'))
    else:
        record = {'phase': 'launch-intent', 'started': time.time(), 'payload': PAYLOAD_HASH}
        save(record)  # A crash from this point requires review, never redispatch.
        encoded = base64.b64encode(payload.decode('utf-8').encode('utf-16le')).decode('ascii')
        launch = qm(['guest', 'exec', '106', '--synchronous', '0', '--',
                     r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded])
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
            raise RuntimeError('Guest cleanup failed or output truncated; evidence retained')
    elif time.time() - record['started'] > 120:
        raise RuntimeError('Guest operation exceeded 120 seconds; no repeat or forced termination')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
