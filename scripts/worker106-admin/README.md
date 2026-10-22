# Standard VM 106 administration

The human explicitly authorized normal remote administration and software
installation on the dedicated test VM. This is a standard pywinrm client, separate
from the closed Proxmox/research controllers. It does not expose a new service.

Verified endpoint: `http://192.168.1.173:5985/wsman`, account
`PASSKEYS-WORKER\AiwWorkerAdmin`, guest UUID
`7e686bee-8c05-43c7-9603-a9562ece224c`, administrator SID ending `1006`.
NTLM message encryption is required (`message_encryption='always'`); Basic/plaintext
transport and certificate-validation bypasses are not used. RDP port 3389 was
reachable, but a fresh RDP login was not tested. The native Windows client failed
its workgroup authentication check; this standard client actually authenticated
and proved an elevated guest session.

Controller prerequisites already installed:

- Python: `C:\Users\labadmin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`.
- Isolated client packages: `C:\passkeys\worker106-tools\winrm-python`.
- DPAPI credential: `C:\passkeys\worker106-tools\worker-admin-recovery\worker-admin.credential.clixml`.

The credential/private key are excluded from Git. The wrapper reads the credential
as the controller user and passes it to Python only through a local stdin pipe,
never as a command-line argument. Each remote script first checks guest UUID and
administrator SID. Larger scripts are compressed in transit to fit WinRM's shell
command-line limit. Commands and their outputs must not intentionally print secrets.

Example on this controller:

```powershell
& C:\passkeys\app-isolation-workbench\scripts\worker106-admin\Invoke-WorkerWinRM.ps1 `
  -ScriptPath C:\passkeys\worker106-tools\remote-identity.ps1
```

The result is JSON with `exit_code`, `stdout` and `stderr`, or a connection error.
Check the actual remote exit code and output, not the outer PowerShell exit code.
Module-initialization progress may appear as CLIXML on stderr without a command
failure. Do not rerun mutating installers blindly after an interrupted call; retain
their intent, process and installer receipts and inspect guest state first.

Installed client versions are retained in `requirements.txt`. Reinstall, if needed,
with the same Python executable using `-m pip install --target
C:\passkeys\worker106-tools\winrm-python -r
C:\passkeys\app-isolation-workbench\scripts\worker106-admin\requirements.txt`.

The earlier fixed QGA management bootstrap failed at WinRM public-profile setup
before its firewall/network stages. Do not run those bootstrap or inventory-only
updaters again. The human enabled the NIC/remoting directly; standard access now
works. Preserve failed journals for history. Snapshot and research-driver trial
gates remain distinct from this successful administration connection.
