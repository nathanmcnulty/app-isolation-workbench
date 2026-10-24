# Historical worker routes are retired

The PowerShell 7.6 migration intentionally retires the old VM106 administration/bootstrap and VM107 research execution graph, including its source-generating templates and deployment tests. Their executable entry points now terminate before credentials, connections, account creation, file transfer or dispatch. No default remoting endpoint, compatibility process, or legacy-runtime fallback remains active. These scripts are not a supported way to prepare a new baseline.

Historical sources are available at commit `7bb40d6a9f3d2ea54774631826cedeadd623e644`; existing evidence remains tied to that runtime and must never be relabeled or replayed. The signed Notepad++ assembly builder, pure preparation-record helpers and extraction-only/native-handle regressions remain supported under stable PowerShell Core 7.6 or newer. They do not establish fresh native application validation.

Use `scripts/vm-msix/transport.ps1` only through the approved production workflow. New runtime installation, endpoint registration, baseline creation and fresh native acceptance require the bundled setup approval. The historical bounded fixture is retired too; its completed nonce must not run again.

Retired entry points:

- `scripts/research/Complete-Worker106TailscaleCleanup.ps1`
- `scripts/research/Connect-Worker106.ps1`
- `scripts/research/Enable-Worker106Management.ps1`
- `scripts/research/Initialize-Worker106.ps1`
- `scripts/research/Invoke-Worker106SchedulerControl.ps1`
- `scripts/research/Prepare-Worker106Offline.ps1`
- `scripts/research/Remove-Worker106TailscaleState.ps1`
- `scripts/research/Save-Worker106Credential.ps1`
- `scripts/research/Show-Worker106Login.ps1`
- `scripts/research/Test-Worker106CredentialReceipt.ps1`
- `scripts/research/Test-Worker106ManagementFirewall.ps1`
- `scripts/research/Test-Worker106ManagementGuard.ps1`
- `scripts/research/Test-Worker106OfflineGuard.ps1`
- `scripts/research/Test-Worker106SchedulerCleanup.ps1`
- `scripts/research/Test-Worker106SetupPreflight.ps1`
- `scripts/research/Test-Worker106TailscaleCleanupGuard.ps1`
- `scripts/research/Worker106-AutologonSecret.ps1`
- `scripts/research/build-worker107-msix-payload.ps1`
- `scripts/research/install-proxmox-vm106-management.sh`
- `scripts/research/install-proxmox-vm106.sh`
- `scripts/research/invoke-worker107-msix.ps1`
- `scripts/research/msix-scheduler-launch-control.ps1`
- `scripts/research/proxmox-vm106-cleanup.py`
- `scripts/research/proxmox-vm106-management.py`
- `scripts/research/proxmox-vm106-prepare.py`
- `scripts/research/proxmox-vm106.sh`
- `scripts/research/proxmox-vm203.sh`
- `scripts/research/proxmox-worker107.sh`
- `scripts/research/test-proxmox-vm106-cleanup.py`
- `scripts/research/test-proxmox-vm106-management.py`
- `scripts/research/test-proxmox-vm106-prepare.py`
- `scripts/research/test-proxmox-vm106.sh`
- `scripts/research/test-worker107-msix-harness.ps1`
- `scripts/research/test-worker107-profile-context.ps1`
- `scripts/research/update-proxmox-vm106-guest-cleanup.sh`
- `scripts/research/update-proxmox-vm106-inventory.sh`
- `scripts/research/update-proxmox-vm106-lock.sh`
- `scripts/research/update-proxmox-vm106-preparation.sh`
- `scripts/research/vm106-scheduler-worker.ps1`
- `scripts/research/worker106-primary/Clear-Autologon.ps1`
- `scripts/research/worker106-primary/Create-Account.ps1`
- `scripts/research/worker106-primary/Render-Application.ps1`
- `scripts/research/worker106-primary/Render-Control.ps1`
- `scripts/research/worker106-primary/Stage-Inputs.ps1`
- `scripts/research/worker106-primary/application-controller.template.ps1`
- `scripts/research/worker106-primary/application-worker.template.ps1`
- `scripts/research/worker106-primary/controller.template.ps1`
- `scripts/research/worker106-primary/prepare.template.ps1`
- `scripts/research/worker106-primary/worker.template.ps1`
- `scripts/research/worker107-editor.ps1`
- `scripts/research/worker107-msix-templates.ps1`
- `scripts/research/worker107-msix.ps1`
- `scripts/research/worker107-preflight.ps1`
- `scripts/research/worker107-reset-profile.ps1`
- `scripts/research/worker107-scheduler-controller.ps1.in`
- `scripts/research/worker107-scheduler-worker.ps1.in`
- `scripts/worker106-admin/Copy-WorkerFile.ps1`
- `scripts/worker106-admin/Invoke-WorkerWinRM.ps1`
- `scripts/worker106-admin/copy-client.py`
- `scripts/worker106-admin/winrm-client.py`
- `scripts/vm-msix/tests/invoke-bounded-windows-fixture.ps1`
