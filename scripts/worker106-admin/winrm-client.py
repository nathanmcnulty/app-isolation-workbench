"""Standard pywinrm client. Credentials arrive only through the parent pipe."""
import json
import sys
import base64
import gzip
sys.path.insert(0, r'C:\passkeys\worker106-tools\winrm-python')
import winrm

request = json.loads(sys.stdin.buffer.read().decode('utf-8'))
try:
    session = winrm.Session('http://192.168.1.173:5985/wsman',
                            auth=(request['username'], request['password']),
                            transport='ntlm', message_encryption='always',
                            operation_timeout_sec=30, read_timeout_sec=40)
    script = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
              "if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c'"
              " -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-21-3849540285-1795134874-2442050430-1006')"
              "{throw 'Wrong worker or administrator'};\n" + request['script'])
    # WinRM's cmd shell has an 8191-character command limit. Compress larger
    # scripts for transport; source stays readable in the local administration file.
    if len(script.encode('utf-16le')) * 4 // 3 > 7000:
        encoded = base64.b64encode(gzip.compress(script.encode('utf-8'))).decode('ascii')
        script = ("$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + encoded + "'));"
                  "$z=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);"
                  "$r=New-Object IO.StreamReader($z);try{& ([scriptblock]::Create($r.ReadToEnd()))}finally{$r.Dispose();$z.Dispose();$m.Dispose()}")
    command = 'powershell -encodedcommand ' + base64.b64encode(script.encode('utf-16le')).decode('ascii')
    if len(command) > 8191:
        raise ValueError('Script exceeds the WinRM shell command limit after compression; split it into smaller scripts')
    result = session.run_ps(script)
    print(json.dumps({'exit_code': result.status_code,
                      'stdout': result.std_out.decode('utf-8-sig', errors='replace'),
                      'stderr': result.std_err.decode('utf-8-sig', errors='replace')}))
except Exception as error:
    print(json.dumps({'connection_error': str(error)}))
    sys.exit(1)
