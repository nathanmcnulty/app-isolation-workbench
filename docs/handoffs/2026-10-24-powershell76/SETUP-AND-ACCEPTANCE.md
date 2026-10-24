# Consolidated PowerShell setup and native acceptance approval

Status: prepared offline; **not executed or approved by adopting GOAL.md**.
One approval may cover the bounded stages below. A narrower approval must name
its stages. Stop on identity/hash/ACL/capability mismatch; do not repair by falling
back to Windows PowerShell, weakening HTTPS, or broad Enable-PSRemoting.

## Exact scope and inputs

- Development/controller: existing VM203, `C:\aiw\app-isolation-workbench`.
  Verified controller UUID `652a575b-a462-418e-95bb-360b28516925`;
  recheck before installation, independently of the worker identity below.
- Disposable worker: **VM107 only**, `aiw-worker`, UUID
  `e5cecc90-35c2-4831-bf9c-424be23f7d4e`, MAC `CC:34:21:B8:5A:31`,
  `192.168.1.174`. Proxmox `pve-r630`, `192.168.1.6`.
- VM106/passkeys-worker is excluded. Never restore VM203.
- Install input: Microsoft's stable **PowerShell 7.6.7 x64 MSI**, released
  2026-10-13, [official release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.7).
  [Exact MSI](https://github.com/PowerShell/PowerShell/releases/download/v7.6.7/PowerShell-7.6.7-win-x64.msi)
  SHA256 `ec575cef9ec56fcd905de0d5eeac9cb7f81a0a65abb87bb5cd0e87fdfe2b8cc0`.
  Verify hash and valid Microsoft Authenticode before any installation. Do not
  resolve a floating latest URL or replace the existing bundled test runtime.
- Desired machine executable/PSHOME: `C:\Program Files\PowerShell\7\pwsh.exe`
  and `C:\Program Files\PowerShell\7` on both machines. No Store/user alias.
- New endpoint: **PowerShell.7.6**, normal HTTPS5986, existing certificate
  `BC14DCC4E37F83161EBB55AF8624E36A79E19256`. Verify certificate trust, name,
  expiry and private-key/listener binding; no TLS bypass or HTTP listener.
- Controller remains VM203 `192.168.1.171`; retain its existing exclusive firewall
  scope. The elevated remoting operator is existing labadmin SID
  `S-1-5-21-3556347314-2314855617-1438300668-1001`. Retain DPAPI credentials
  without printing, exporting or creating replacement credentials/private keys.

## Stage A: install the exact runtime

Approval includes machine-wide installation on VM203 and VM107, with no automatic
remoting/firewall/endpoint enablement. Stage MSI into a fresh private directory,
for example `C:\ProgramData\AIW-Core76-Setup-20261024`; retain install diagnostics
outside Git. Run the verified native Windows installer with these fixed settings:

```text
C:\Windows\System32\msiexec.exe /i C:\ProgramData\AIW-Core76-Setup-20261024\PowerShell-7.6.7-win-x64.msi /qn /norestart ENABLE_PSREMOTING=0 REGISTER_MANIFEST=0 ADD_PATH=0
```

Accept exit0; treat3010 as a separately recorded reboot requirement before use.
Verify the exact installed executable's SHA256, numeric version7.6.7, Core edition,
empty prerelease, x64 architecture, canonical image/PSHOME and native capability
proof. The host must not run application installers or validation applications.

The current forced SSH key permits the reviewed provider verbs only. It does not
grant generic Proxmox management or a bootstrap shell. Worker installation therefore
requires operator execution through the existing Proxmox root console/QEMU guest
agent (or another explicitly approved management route); do not broaden that key
or create credentials as a shortcut. A native QEMU guest-exec bootstrap may launch
the verified MSI and then the **installed Core executable directly**. It must not
invoke a legacy PowerShell bootstrap or infer the guest runtime from the caller.

## Stage B: register the endpoint without broadening access

Use the installed Core executable after its in-guest runtime and UUID proof.
Retain the prior endpoint/listener/ACL inventory. Register only `PowerShell.7.6`
using basic `Register-PSSessionConfiguration -Name PowerShell.7.6` registration,
explicit `-ProcessorArchitecture amd64`, `-UseSharedProcess:$false` and
`-NoServiceRestart`, with the restricted security descriptor below. Do not use
`-Path`, a PSSC/ConfigFilePath, RunAs, startup script or custom initialization.
The closed proof requires the sole initialization parameter `PSVersion=7.6`,
not the generic install script's `7.0`. Verify the actual Registry64 ConfigXML,
resource URI, Resource SupportsOptions, registered plugin and adjacent
RemotePowerShellConfig.txt redirects to the fixed PSHOME/CORECLRDIR. Endpoint
access is restricted to the exact
labadmin SID above and SYSTEM, with owner/group Administrators; no Everyone,
Authenticated Users, anonymous or general Remote Management Users grant.

Registration and any required **WinRM restart** are part of this approval stage.
Use no-service-restart registration followed by an explicit recorded restart.
Retain the existing sole HTTPS listener and controller-only firewall rules;
do not call broad `Enable-PSRemoting`, change TrustedHosts, or enable HTTP.
Prove the actual wsmprovhost.exe host, loaded Core assembly path/hash/version/MVID,
registered configuration/plugin, PSHOME and native modules through Invoke-Command
in the same session used by Copy-Item. Independently launch and prove the fixed
worker pwsh.exe and bind both distinct identities; an endpoint name or installed
file alone is insufficient. Only after this proof may
the superseded `Microsoft.PowerShell` management endpoint be disabled; record that
security change and verify normal HTTPS access again. On failure preserve state
and use the approved Proxmox recovery route, without enabling fallback endpoints.

Native proof must demonstrate Appx (per-user deployment, not provisioning as a
substitute), DISM inventory, CIM, LocalAccounts, ScheduledTasks, WSMan/certificate
providers, relevant COM and Add-Type with implicit compatibility disabled. Reject
proxy modules, WinPSCompatSession and Windows PowerShell child processes. Native
imports observed on the controller do not establish these worker operations.

## Stage C: create and bind a fresh clean baseline

First prove no foreign/dirty lease, no trial accounts/tasks/package/process/raw
artifacts and disabled automatic sign-in. Preserve the historical TLS-clean
snapshot and all completed run evidence. With VM107 stopped and its NIC down,
create **aiw-msix-worker107-pwsh76-clean-r1**, covering OS, EFI and TPM with no RAM.
Never overwrite or relabel `aiw-msix-worker107-tls-clean-r1`.

Reopen/inspect the actual new snapshot and compute its real configuration hash.
Update the fixed provider/checkpoint pins coherently only from that observation,
deploy its exact reviewed wrapper bytes, verify them remotely, then cold-restore
and prove runtime/endpoint/account/task/package/process cleanliness survives.
The offline checkpoint deliberately retains the deployed historical provider's
pins; acquisition of that baseline for migrated execution fails before mutation.
No guessed future snapshot config hash or fabricated runtime receipt is published.
The approval bundle must include the resulting observed pin updates and their
separately identifiable validation checkpoint; no future pin is guessed here.

## Stage D: fresh minimal-purpose native acceptance

Approval covers new plan/request/nonce/preparation and fresh evidence/export roots
under `C:\AIW-Resume-20261021\powershell76-native-<fresh run ID>`; derive actual IDs
from typed preparation records, not from any historical completed run. Build only
from the sanitized checkpoint and retain its exact worker/desktop/script hashes.

Use the fixed signed Notepad++8.9.8 recipe. Package SHA256
`2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437`, assembly
SHA256 `d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38`,
signing metadata SHA256 `670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80`.
Use existing verified inputs at `C:\AIW-Resume-20261021\assets\inputs` only after
rechecking their held identities; do not patch the signed application package.

Prove SYSTEM and fresh standard-user Core runtime identities, delayed active
interactive session/profile readiness, exactly one native Control42, then the
explicitly approved install/open/edit/save/close/uninstall lifecycle. The target
document is the request's exact run-owned profile path; append `AIW packaged
validation` plus Enter, save and close. Retain original document bytes/hashes,
native process/job/session/token/runtime receipts, package inventory and absence
checks. Test authoritative raw recovery with missing/partial caches and blocked
export/queued tasks in fresh bounded fixture runs. No automatic dispatch retry.

Export originals durably before cold rollback. A collection/completeness failure
retains the exact dirty lease; a completed cold clean proof precedes release.
Finish by verifying normal TLS, exactUUID, baseline accounts, no trial artifacts,
disabled automatic sign-in and leasePresent=false. Keep full app trial results
separate from bounded fixtures; compatibility/isolation remain unmeasured.

Completed runs `msix-1792704525359564000` and
`msix-bounded-1792816990610240800` must never be replayed or recovered. PR103 remains
unmerged throughout. Runtime/security/native setup approval does not authorize
merging, credential reconfiguration, changing VM106, or public/private-key upload.
