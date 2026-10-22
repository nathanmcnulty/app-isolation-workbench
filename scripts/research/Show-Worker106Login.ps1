# Controller-only private credential display for the human console sign-in.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$credential=Import-Clixml -LiteralPath 'C:\passkeys\worker106-tools\worker-admin-recovery\worker-admin.credential.clixml'
$message="VM 106 / PASSKEYS-WORKER`r`n`r`nUser: .\AiwWorkerAdmin`r`nPassword: "+$credential.GetNetworkCredential().Password+"`r`n`r`nEnter these directly in the Proxmox console. Keep the network disconnected."
[void][Windows.Forms.MessageBox]::Show($message,'VM 106 private console login',[Windows.Forms.MessageBoxButtons]::OK,[Windows.Forms.MessageBoxIcon]::Information)
$message=$null;$credential=$null
