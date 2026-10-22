"""Standard encrypted PSRP file transport; credentials arrive through stdin."""
import hashlib
import json
import os
import sys

sys.path.insert(0, r'C:\passkeys\worker106-tools\psrp-python')
from pypsrp.client import Client
import spnego

# Match requests-ntlm's explicit-credential behavior: use its pure NTLM backend
# rather than Windows SSPI, which rejects this cloned workgroup-machine context.
# This changes only the local protocol implementation; sealing stays mandatory.
_spnego_client = spnego.client
def explicit_ntlm_client(*args, **kwargs):
    if kwargs.get('protocol') != 'ntlm':
        raise RuntimeError('Only explicit NTLM is supported by this worker client')
    kwargs['options'] = kwargs.get('options', 0) | spnego.NegotiateOptions.use_ntlm
    return _spnego_client(*args, **kwargs)
spnego.client = explicit_ntlm_client

request = json.loads(sys.stdin.buffer.read().decode('utf-8'))
try:
    with Client('192.168.1.173', username=request['username'], password=request['password'],
                ssl=False, auth='ntlm', encryption='always') as client:
        guard = ("$ErrorActionPreference='Stop';"
                 "if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c'"
                 " -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-21-3849540285-1795134874-2442050430-1006')"
                 "{throw 'Wrong worker or administrator'};")
        output, streams, failed = client.execute_ps(guard + "'verified'")
        if failed or output.strip() != 'verified':
            raise RuntimeError('Worker identity check failed before transfer')
        remote = request['source'] if request['fetch'] else request['destination']
        quoted = "'" + remote.replace("'", "''") + "'"
        if request['fetch']:
            if os.path.lexists(request['destination']):
                raise RuntimeError('Local destination already exists; preserve previous evidence')
            client.fetch(request['source'], request['destination'])
            local = request['destination']
        else:
            output, streams, failed = client.execute_ps(guard + "if(Test-Path -LiteralPath " + quoted + "){throw 'Destination exists'};'fresh'")
            if failed or output.strip() != 'fresh':
                raise RuntimeError('Remote destination exists or could not be checked')
            client.copy(request['source'], request['destination'])
            local = request['source']
        with open(local, 'rb') as source:
            local_hash = hashlib.file_digest(source, 'sha256').hexdigest()
        output, streams, failed = client.execute_ps(guard + "(Get-FileHash -LiteralPath " + quoted + " -Algorithm SHA256).Hash.ToLowerInvariant()")
        if failed or output.strip() != local_hash:
            raise RuntimeError('Transferred file SHA-256 differs; preserve partial transfer')
        print(json.dumps({'transferred': True, 'fetch': request['fetch'], 'sha256': local_hash,
                          'source': request['source'], 'destination': request['destination']}))
except Exception as error:
    print(json.dumps({'transfer_error': str(error)}))
    sys.exit(1)
