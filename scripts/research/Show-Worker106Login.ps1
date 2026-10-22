# Controller-only private credential display for the human console sign-in.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$credential=Import-Clixml -LiteralPath 'C:\passkeys\worker106-tools\worker-admin-recovery\worker-admin.credential.clixml'
$form=[Windows.Forms.Form]::new()
$form.Text='VM 106 private console login'
$form.ClientSize=[Drawing.Size]::new(760,210)
$form.StartPosition='CenterScreen';$form.TopMost=$true
$label=[Windows.Forms.Label]::new()
$label.Text="VM 106 / PASSKEYS-WORKER`r`nUser: .\AiwWorkerAdmin`r`nPassword (select to copy, or type in the Proxmox console):"
$label.Location=[Drawing.Point]::new(18,15);$label.Size=[Drawing.Size]::new(720,65)
$box=[Windows.Forms.TextBox]::new()
$box.ReadOnly=$true;$box.Text=$credential.GetNetworkCredential().Password
$box.Font=[Drawing.Font]::new('Consolas',14)
$box.Location=[Drawing.Point]::new(18,85);$box.Size=[Drawing.Size]::new(720,35)
$note=[Windows.Forms.Label]::new()
$note.Text='Keep the worker network disconnected. Tell Codex once you reach the fresh account desktop.'
$note.Location=[Drawing.Point]::new(18,140);$note.Size=[Drawing.Size]::new(720,45)
$form.Controls.AddRange(@($label,$box,$note))
try {[void]$form.ShowDialog()} finally {$box.Text='';$credential=$null;$form.Dispose()}
