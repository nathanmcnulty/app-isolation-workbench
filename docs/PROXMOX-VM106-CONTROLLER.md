# VM 106 isolated worker controller

**Current operational path:** standard WinRM at 192.168.1.173 is authenticated
and elevated; Windows preparation is finalized. Use
[worker106-admin](../scripts/worker106-admin/README.md). The historical bootstrap
instructions below are retained evidence, not next steps. Do not run them again.
Baseline `aiw-vm106-baseline-20261021` now exists, created with the worker stopped
and no saved memory. The helper accepts Proxmox's exact canonical enabled NIC
form. See the repair/baseline receipt at the end; historical pending statements
below describe the earlier stopping points.

This is a research setup boundary for the Proxmox clone `passkeys-worker`, not application acceptance. The operator confirmed it is stopped, has a new MAC and disconnected network, and has automatic start disabled. Keep the original PASSKEYS VM as the controller.

## Source and authority

The current helper is preserved at commit `184022c052db84e2a31a9eeee7defdfd07066a35`, SHA-256 `d51cec1cca050118063758a09a43fd8af7e36cac8834e4775fc1273bd3326955`. Its tree matches locally reviewed lock-fix commit `caa66f840eda3093e3394214ea1efa2b53e28e5c`. Publication used the connected GitHub integration because GitHub CLI credentials had expired. The source was downloaded again and its hash verified. The first deployed version was commit `61a531708633cda4dad9708e5ff1af887072d541`, hash `7a6454f5478f2a89cfa034e962818a39e8d0a50db80cbb28acfff9ea0c1c006c`; it must be upgraded before further use.

The helper pins host `pve-r630`, VM 106, name `passkeys-worker`, SMBIOS UUID `7e686bee-8c05-43c7-9603-a9562ece224c`, EFI/OS/TPM disks on `r630-fast2`, `net0` MAC `CC:34:21:7E:FE:59` with `link_down=1`, `onboot=0` and the guest agent. It rejects pending configuration changes, additional network adapters, arbitrary QEMU arguments, PCI/USB passthrough and host hooks.

Exact SSH command strings `inspect`, `status`, `shutdown`, `start`, `snapshot`, `rollback` and `worker-cleanup` are accepted. No caller arguments, shell evaluation, clone, arbitrary guest execution, network changes, snapshot deletion or arbitrary target selection exists. Baseline `aiw-vm106-baseline-20261021` creation requires stopped state and records no memory. An existing baseline cannot be replaced. Rollback requires stopped state and matching snapshot identity/disconnected configuration; memory-state snapshots are rejected.

The root-owned lock serializes this helper's calls, not independent administrators or automation. Descriptor 9 stays in the waiting helper shell and is closed in every qm/pvesm child; lock contention reports exit 75. Avoid concurrent out-of-band configuration changes. Root-owned helper/key files, normal SSH environment restrictions and protected snapshot custody remain deployment assumptions. This does not measure application compatibility or effective isolation.

## One operator step

Run [install-proxmox-vm106.sh](../scripts/research/install-proxmox-vm106.sh) once in the **root shell on pve-r630**. It downloads the immutable helper, checks its independent hash and syntax, and performs read-only identity/storage inspection before installation. It refuses an existing helper or a symlinked `/root/.ssh` directory. A symlinked `authorized_keys` is accepted only when its canonical target is the existing root-owned mode-600 `/etc/pve/priv/authorized_keys`; other targets are rejected. The Proxmox-managed target is appended to without changing its ownership or permissions. This managed file is cluster-shared; the key's forced command still pins the host and VM, and no helper is deployed to other nodes. An ordinary regular `authorized_keys` file is also supported. The installer writes `/usr/local/sbin/aiw-vm106` root-owned mode 755 and appends the dedicated public key with `restrict,command="/usr/local/sbin/aiw-vm106"`. The private key remains on the controller and was generated after cloning.

Expected completion: configuration/status/snapshot/storage output, then `Installed restricted VM 106 helper; worker remains stopped and disconnected.` and the helper hash above. On error, preserve output; do not weaken checks or overwrite an existing helper. No worker boot, snapshot or rollback is part of installation.

The controller's local `C:\passkeys\worker106-tools\ssh_config` pins the operator-verified Ed25519 host fingerprint `SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E`, uses its dedicated key, disables interactive fallback/forwarding, and requires strict host-key checks. The first live call after installation will be read-only `inspect`.

## Validation and next step

37 credential-free mocked dispatch/identity checks passed, including command injection, caller arguments, wrong host/root/VM fields, pending config, alternate networking, running-worker snapshot/rollback, snapshot drift, memory state, missing baseline and busy-lock rejection. The mock also requires an open lock descriptor at acquisition and rejects any qm/pvesm child inheriting it. The original helper failed that descriptor regression. Shell parsing and governance checks passed; independent lock-fix review found no actionable findings. Mocks do not establish live recovery or complete application acceptance.

### Observed first-boot failure and bounded recovery

Host installation succeeded, strict-host-key SSH inspection matched the stopped/disconnected worker, and an unsupported verb was rejected with exit 64. The fixed start command returned success. Subsequent valid calls returned exit 1 with no output. Operator readback confirmed the VM was running and current/default configurations were unchanged. `lslocks` and `fuser` identified swtpm PID 914465 holding the helper lock and kvm PID 914470 also retaining the file. These process IDs describe that observation only and are not cleanup targets.

The initial helper let its lock descriptor propagate into Proxmox children. The correction closes that descriptor in qm/pvesm children and prevents tail execution while the parent retains lock custody. Do not unlink the lock file or kill the observed process IDs. The reviewed [one-time lock recovery](../scripts/research/update-proxmox-vm106-lock.sh) requires the exact old helper hash, verifies the downloaded fixed version, checks target identity and performs graceful shutdown with a 120-second deadline. It then requires stopped state and successful full read-only inspection through the fixed helper, acquires the existing lock, rechecks stopped state/old hash, and atomically replaces only that helper. It preserves SSH keys and the lock inode. If the lock remains held or shutdown fails, it stops without force-stop or code replacement.

The operator completed that recovery and supplied the exact fixed-helper hash. A subsequent strict-host-key SSH cycle passed all six steps: stopped inspection, start, running status, running inspection, graceful shutdown and stopped status. Calls after start succeeded while the VM was running, closing the observed lock-inheritance regression. Final state is stopped, with `link_down=1` and no snapshots. Detailed per-step UTC/exit/output records remain on the controller in `C:\passkeys\worker106-tools\lock-fix-live-cycle-20261021`. This verifies the bounded power/readback path; snapshot/rollback, guest setup and application acceptance are still untested on this worker.

After live read-only inspection, prepare Windows identity/auth-state cleanup and separate worker access. Do not start copied Codex/Tailscale sessions or adopt browser/GitHub/Azure caches. Arrange real standard-user login before a time-limited window. Rebind and independently review the historical Azure-pinned driver/controllers for the actual worker. Before allowing network changes, review a new exact network binding; this initial helper deliberately rejects connected-network configurations. Take the actual baseline only after worker preparation, then prove the fixed Scheduler WTS control before the signed MSIX lifecycle. Export evidence to the controller before rollback. Provider Hello/Key Vault/RP trials remain separate.

## Fixed guest-agent cleanup

Manual console setup reached the elevated labadmin desktop on the disconnected
worker. Tailscale was uninstalled; the operator confirmed its service, ProgramData
state and legacy SYSTEM state absent, with only labadmin's local Tailscale folder
remaining. The old cleanup script stopped safely because it expected both folders
to exist. WorkplaceJoined remains YES in the copied profile; no Windows/cloud
registration removal was authorized or performed.

The new `worker-cleanup` operation runs only the hash-pinned
`Complete-Worker106TailscaleCleanup.ps1` through the guest agent as 64-bit SYSTEM.
It rechecks the guest UUID, exact disconnected physical adapter and absent service,
validates the three fixed local Tailscale paths for junctions/reparse points, and
removes only existing directories. Missing directories are accepted. This is
offline file cleanup, not a server-side logout or whole-profile sanitization.
Do not run concurrent guest filesystem changes during cleanup.

`proxmox-vm106-cleanup.py` has no command/PID arguments. A durable root-only host
journal at `/var/lib/aiw-vm106/cleanup.json` records launch intent before dispatch,
then the returned PID, collection intent and final captured result. A repeated
call polls that PID or returns its retained result; ambiguous launch/collection
failures stop for review without redispatch. CLI calls have a 35-second deadline;
a running guest exceeding 120 seconds is reported, never silently killed/repeated.
Do not delete the journal to retry. Snapshot rollback does not reset this host
journal. This operation does not prepare fresh accounts or measure app acceptance.

The CLI's asynchronous PID and exec-status contract is documented in the
[official Proxmox command synopsis](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc).
The fixed operation and journal are mock-tested; live guest-agent availability
and actual cleanup remain unmeasured until the host update and result readback.

Install the one-time host update from commit
`e914d9a1ad3226e587399844d38c88732b640782`:
`scripts/research/update-proxmox-vm106-guest-cleanup.sh`, SHA-256
`b9580ac94739f8009cd391b332a48931f491b3505f41fa8a804ae8c4833bda34`.
It requires the deployed d51cec1c helper, verifies three immutable input hashes,
checks full VM identity and a guest-agent ping, establishes root-protected payload
and journal paths, and activates the helper last. It does not launch guest code.
On a partial installation failure preserve output/files for review, rather than
rerunning or deleting state. Expected final line:
`Fixed VM 106 guest cleanup installed; guest agent responds; no guest operation launched.`
The resulting helper hash is
`beb5652a928a06be69c167fc68073a5147af6f0e769db9ee47c0a2233bd507be`.

39 mocked dispatch/identity checks and six journal/process tests passed. Shell and
PowerShell parsing passed. Independent reviews of the operation and updater found
no actionable findings. Published source downloads matched all three input hashes.
The fixed cleanup is published at `48038f402f8d16b78ac65229eccdc606cd94aa87`,
matching locally reviewed tree `14fc72a7c2e35d3d8a6a8f7b56091ff546b7ebf6`.

### Live cleanup result

The operator installed the update and supplied the expected helper hash. At
2026-10-22 04:53 UTC, the strict-key SSH `worker-cleanup` call launched the fixed
payload and returned PID 6980 with phase `running`. The next call collected that
same PID: phase `finished`, exited 1, exitcode 0, output not truncated. Here
`exited: 1` means completion, not an error code. The guest JSON identified the
expected UUID, reported ServicePresent/ProgramDataState/UserState/LegacyState all
false, and recorded removal of only the labadmin local Tailscale directory.
Network remained Disconnected and WindowsRegistrationChanged was false.

Raw first-call/result records and the parsed checked receipt are retained under
`C:\passkeys\worker106-tools\guest-cleanup-live-first.json`,
`guest-cleanup-live-result.json`, and `guest-cleanup-verified.json`. The durable
host journal remains `/var/lib/aiw-vm106/cleanup.json`. No retry, reboot, network
change or snapshot was performed. This completes the bounded Tailscale cleanup;
fresh worker accounts, other copied authentication state, driver rebind and
application trials remain separate outstanding work.

## Remaining offline preparation contract

The remaining setup uses fixed `worker-prepare`, `worker-verify`,
`worker-finalize` and read-only `worker-preparation-state` operations, activated by one reviewed host update. All retain
the existing host/VM/disconnected-network checks and run fixed hash-bound guest
payloads as SYSTEM. Preparation requires the original computer name and copied
labadmin SID, no machine domain/Entra join, completed Tailscale cleanup, and no
existing setup/account. It creates a protected stage before mutation, generates
a fresh administrator password inside the worker, and stores only its RSA-OAEP
ciphertext in the stage/host result. The recovery private key remains DPAPI-sealed
on the controller. No credential is printed or committed.

Preparation creates AiwWorkerAdmin and a new profile, validates its credentials
with LogonUser, disables the two copied Codex sandbox users, and stages the
PASSKEYS-WORKER rename. It retains labadmin for recovery. Existing shutdown/start
operations perform the reboot; post-boot verification measures name, accounts,
profile, runtime/tool paths, cleanup and device join flags. Tool paths under the
old profile are reported separately rather than adopted as fresh-user tooling.

The operator still signs into the fresh administrator through the Proxmox console
using a private controller credential file. Finalization requires that exact
account at the interactive console before disabling copied labadmin. This is not
a standard-user application trial. The trial account and timed window remain
deferred. Windows registration and copied profile/cache deletion remain outside
this preparation; the disconnected network stays enforced. Create the stopped
baseline only after finalization and verification pass. On ambiguous dispatch or
partial setup retain journals, credentials and evidence; never repeat blindly.
The state operation retrieves the protected setup record, including encrypted
credential recovery material, even after partial setup. Read-only state and
verification operations archive completed host observations before measuring
again. They never relaunch an ambiguously dispatched guest process.

### Pinned preparation update and execution order

Source is published at `4d80297b349fcf7aed0761bd307f3d1464bacb13`, tree
`7fb2d821f2522b3a2dd58b314d17b5f312525e5b`. The host updater is
`scripts/research/update-proxmox-vm106-preparation.sh` at commit
`6cc8d7373169dab23ce303626b32a273e94407f9`, SHA-256
`d163b990e7fc8157d700dba57a632f8676885e1ee5cd8155128b23dc5369daab`.
It requires the deployed beb5652a helper and successful retained cleanup journal,
then verifies inputs and root-protected installation paths. It adds the two fixed
preparation files and atomically activates the helper last, without running setup,
changing SSH keys, rebooting, or connecting networking. Preserve partial updates
for review. Expected completion:
`VM 106 offline preparation operations installed; no guest setup launched.`
Resulting helper SHA-256:
`64651fd9ff51368a858f700c7387c25d0525d4f7c4dc9f22fc36028cc4c844a0`.

Controller execution order after operator update:

1. Call `worker-prepare` through the existing strict-key SSH configuration, retain
   raw output as `C:\passkeys\worker106-tools\preparation-result.json`, and poll
   its saved PID to completion. Do not reboot while setup is still running.
2. Run `Save-Worker106Credential.ps1` on the controller to recover only into a
   DPAPI CurrentUser credential file. The precreated recovery directory grants
   access only to controller labadmin and SYSTEM. The private key is DPAPI-sealed
   and never leaves the controller; all published key material is public.
   If preparation failed after account creation, collect `worker-preparation-state`
   into `preparation-state-result.json` and use `Save-Worker106Credential.ps1
   -Receipt State` instead. This writes a separate partial-recovery credential
   file and preserves the recorded validation/phase; it does not retry setup or
   claim that failed preparation completed.
3. Gracefully `shutdown`, require stopped status, then `start`. Once guest agent
   is responsive, call `worker-verify` and retain its post-boot measurement.
4. Run `Show-Worker106Login.ps1` locally only when the human is ready. It displays
   the credential in a private Windows dialog, without printing to shell/history.
   Human signs into `.\AiwWorkerAdmin` on VM 106 through Proxmox console.
5. Re-measure with `worker-verify`. Only when fresh admin is the interactive user
   with the expected loaded profile, call `worker-finalize` and retain its result.
   Verify again, gracefully shut down, create the fixed stopped baseline, inspect
   it, and start the worker when needed. No timed standard-user trial begins here.

45 mocked helper dispatch/identity checks, 12 negative preparation identity
checks, and seven preparation journal tests passed. A large-script stdin control
passed under Windows PowerShell 5.1; native declarations compiled without being
invoked, the atomic directory-ACL overload was present, and a PS5.1 RSA-OAEP-SHA256
encryption / controller DPAPI-private-key decryption control passed. Governance,
PowerShell and shell parsing checks passed. These checks do not prove live account
creation, CreateProfile/LogonUser execution, reboot or fresh-console finalization;
retain those observations separately when performed. Copied-profile Rust/user
toolchains are not adopted; builds remain on the controller, while verification
checks system-installed runtimes/SDK tools on the worker.

### Live preparation, 2026-10-22 UTC

Operator installation returned the expected 64651fd9 helper hash. Strict-key SSH
`worker-prepare` launched PID 280 at 05:20 UTC; collection returned exited 1,
exitcode 0, no output truncation, Phase PreparedAwaitingReboot. The fixed guest
receipt records new administrator SID `S-1-5-21-3849540285-1795134874-2442050430-1006`,
profile `C:\Users\AiwWorkerAdmin`, and successful credential LogonUser validation.
The two copied sandbox users were disabled and rename staged. Labadmin remained
enabled; no standard trial user was created. The stderr CLIXML contains progress
and the expected rename/restart warning, not an execution failure.

Controller credential recovery succeeded into DPAPI CurrentUser storage without
printing plaintext. The private key and credential remain only in the protected
controller recovery directory; do not put them in Git or the worker. Graceful
shutdown returned success at 05:20:54 UTC; stopped readback passed and start
returned success at 05:21:16 UTC. `swtpm_setup: Not overwriting existing state file`
was retained as start output. No snapshot or network change occurred.

Local nonsecret evidence: `preparation-first-call.json`, `preparation-result.json`
(contains only encrypted credential material), `preparation-verified-summary.json`,
`credential-recovery-receipt.json`, `preparation-shutdown.json` and
`preparation-restart.json`, under `C:\passkeys\worker106-tools`. Post-boot identity,
tool inventory and human console sign-in still require their own receipts.

Post-boot Verify PID 4472 finished at 05:23 UTC with exitcode 1:
`Required system tool path missing`. Its completed journal and controller copy
`preparation-postboot-verify-failed-original-path.json` are retained. Because the
payload reached that check, its preceding name PASSKEYS-WORKER, account SID/group,
copied sandbox disablement and fresh profile registration guards passed. It did
not emit a complete tool inventory, so no missing-worker-tool identity is claimed.

The verifier incorrectly assumed an MSI PowerShell installation. On the controller,
the installed PS7.6.7 execution alias resolves to PSHOME
`C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.7.0_x64__8wekyb3d8bbwe`;
the MSI path is absent. Corrected payload source at
`dcef8bef278951514dbdbf278ddb053f8e51ac4f` uses that exact global package binary
plus Windows PowerShell 5.1, and emits the complete inventory before any missing
path error. All eight paths exist on the controller; guest presence and fresh-user
PS7 registration/execution remain unmeasured until their own checks. The seven
journal tests passed again and independent review found no actionable payload
finding. A selectable private credential dialog was opened in controller session
1; no password was printed or automatically copied.

The corrective updater is `scripts/research/update-proxmox-vm106-inventory.sh`
at `592fcaa8c35f8c73fe83ad0f2ef5fce2075517bc`, SHA-256
`33d31c8d9c9d0ec6689ed23106a8410d48b06951d7acbc1d1d91bfc02a194864`.
It verifies the expected helper before executing inspection, holds the existing
lock, rechecks deployed file hashes, requires all existing preparation-operation
journals finished and Prepare successful, then replaces only the two fixed
payload/runner files. It does not change accounts, credentials, journals, helper,
network or power. The expected new payload/runner hashes are
`fb561897488440a1cb89859f988e3e4e2e807e7ab4832d4b2cc53b8d60700182` and
`ac547718637d6518c7acef468c1e5daf9e473660d137941a144e0dd22e937755`.
Shell parsing passed; independent review's initial verify-before-execute ordering
finding was fixed and confirmed. Preserve partial updates for review. After host
update, collect a fresh Verify observation without rerunning Prepare; the old
Prepare hash remains a deliberate refusal if account setup is requested again.

## Standard remote management requested by the human

The human reports AiwWorkerAdmin is signed in at the desktop and explicitly asks
for remote PowerShell/SSH/RDP to end console work. This authorizes standard remote
administration; it does not make arbitrary input part of the research controller.
The older inventory-only correction above is superseded by this management path.

`install-proxmox-vm106-management.sh` at commit
`9ede7a350b33cb1897da834847192b4bad8c67a7`, SHA-256
`a6e9b290b0d7d30db667ee67e2021df69cafe6a837751d0fe1535391fad51353`,
requires the deployed 64651fd9 helper, completed prior guest operations and a
disconnected NIC. It checks protected paths, immutable inputs and existing helper
hash before execution; installs new payload/runner then activates the helper last
under the retained lock. It runs only the fixed bootstrap, polling for up to 240
seconds. Preserve failures/partial installations; never reinstall to retry.

Bootstrap stages:

1. Guard requires the exact VM/MAC/SYSTEM identity, new administrator SID 1006,
   and actual fresh-administrator console identity with its loaded profile. It
   exports the old firewall policy into the protected management stage, configures
   remoting while offline, disables other endpoints and HTTP listeners, and
   disables copied labadmin only after that console proof. It enables the needed
   local-account administrative token policy. All firewall profiles become enabled
   with default inbound/outbound block; prior local allow rules are disabled.
   Three exact interface-bound exceptions permit controller 192.168.1.165 to TCP
   5986 and DHCP service UDP 68/67 only to/from the LAN/broadcast. Effective rule
   direction, protocol, ports, addresses, interface, service, program, profile and
   edge policy are checked. DHCP is enabled before link-up and copied manual or
   controller-address bindings are removed while disconnected.
2. The host accepts only a just-collected Guard launched within 180 seconds before
   one-time activation. It journals intent and sets only the pinned NIC link flag
   to 0. A later disconnection cannot be undone using the cached Guard. Ambiguous
   guest launch/collection stays blocked; no guest process is silently repeated.
3. Bind waits for a unique 192.168.1.x/24 address on the pinned NIC, excluding the
   controller, router and Proxmox host. It creates a non-exportable 3072-bit RSA
   server certificate with an explicit IP SAN and HTTPS-only listener. DER and
   thumbprint, never private key/password, are retained through authenticated QGA.
4. `Connect-Worker106.ps1` validates the QGA record and source hash, imports only
   that public certificate into controller CurrentUser Root, records its thumbprint
   and removal path, and uses normal TLS validation. No Skip switches or TrustedHosts
   are used. The exact same firewall verifier is carried into the authenticated
   remote proof, together with guest UUID/SID/admin token, MAC/IP, listener binding
   and service checks. Only a passing proof returns a standard PSSession.

Explicit local credentials use Basic authentication only inside validated HTTPS;
unencrypted transport, HTTP listeners, CredSSP, Negotiate and Kerberos are disabled
on this worker. This avoids duplicate-machine-SID NTLM failures documented by
[Microsoft](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/10/kerberos-and-ntlm-authentication-failures-due-to-duplicate-sids),
without weakening that OS protection or changing machine SID. Remote UAC behavior
and HTTPS workgroup access are documented in
[Microsoft's remoting troubleshooting guide](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-5.1).

The new fixed Proxmox helper accepts the same pinned MAC/bridge in exactly link
states 0 or 1, so it remains usable after activation. New closed verbs are
`worker-access`, `worker-access-info` and `worker-disconnect`; the last only sets
that NIC offline. Existing offline-only preparation operations remain historical
and will fail their guest guards when connected. Final Windows preparation now
uses the human-authorized standard remote administration channel.

Readiness evidence: 51 mocked helper dispatch/identity checks, 12 management
transition/journal tests, 11 negative identity cases, 13 firewall-broadening
rejections, and two accepted firewall address forms passed. An actual Windows
PowerShell 5.1 certificate control produced the intended IP SAN/server-auth EKU
and was deleted with its private key. Read-only controller firewall inspection
found all 254 active allow rules came from PersistentStore; no extra policy-store
allows were found. Independent review's cached/aged guard and partial-firewall
findings were fixed; final installer review found no actionable findings.
These are preparation/control observations, not a live remote connection proof.

## Actual standard remote administration and finalization

The management Guard PID 7164 failed at `Enable-PSRemoting` with the WinRM
Public-profile firewall exception error, despite SkipNetworkProfileCheck. Its
finished exit-1 journal and controller readback
`management-bootstrap-error-readback.json` are preserved. Failure occurred before
custom firewall restrictions, copied-labadmin disablement, DHCP changes or link
activation; do not describe those planned restrictions as active configuration.
The human then enabled the NIC and PSRemoting directly, reported address
192.168.1.173, signed into the fresh administrator, and explicitly authorized
normal administration/software installation on this dedicated VM.

TCP 5985 and 3389 were reachable; 5986 and 22 were closed. Native New-PSSession
failed a workgroup authentication check. Standard pywinrm 0.5.0 with NTLM and
`message_encryption='always'` authenticated successfully without modifying
controller TrustedHosts or enabling unencrypted/Basic transport. The actual
remote result identified PASSKEYS-WORKER, UUID
`7e686bee-8c05-43c7-9603-a9562ece224c`, user AiwWorkerAdmin SID
`S-1-5-21-3849540285-1795134874-2442050430-1006`, and an elevated token. The
committed client additionally checks UUID/SID before every script. Source and
exact dependency versions are in `scripts/worker106-admin`. Its credential is
read from the protected controller DPAPI file and passed only through a local
stdin pipe. RDP reachability is not a tested authenticated RDP session.

Actual guest inventory verified Ethernet MAC CC-34-21-7E-FE-59 / address
192.168.1.173/24, loaded fresh profile C:\Users\AiwWorkerAdmin, all four fresh-user
join flags NO, Tailscale service and all three fixed state paths absent, .NET
Core/ASP.NET/Desktop 10.0.13, Node 24.20.0, Git 2.55.0.windows.5, VS installer and
Windows SDK 26100 MakeAppx/SignTool paths present. Store PowerShell 7.6.7 existed
but fresh-account execution failed Access Denied; file existence alone was not
readiness.

The official [PowerShell 7.6.7 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.7)
MSI was downloaded inside VM 106, matched independently supplied SHA-256
`EC575CEF9EC56FCD905DE0D5EEAC9CB7F81A0A65ABB87BB5CD0E87FDFE2B8CC0`, and had a
Valid Microsoft Corporation Authenticode signature. Silent machine-wide install
returned 0; `C:\Program Files\PowerShell\7\pwsh.exe` then actually returned 7.6.7
as AiwWorkerAdmin. Log/intent/receipt remain under guest
`C:\AIW-Worker-Setup\PowerShell-7.6.7-system`; the controller retained
`standard-winrm-powershell7-install.json`.

Finalization through the authenticated elevated session rechecked UUID/SID and
the real loaded fresh-administrator console profile, disabled copied labadmin and
both sandbox users with readback, and preserved before-state copies before marking
the guest setup Finalized / standardRemoteAdministrationReady. Failed custom
management metadata was marked Superseded, with its original state copy retained.
No copied-profile/cache deletion or cloud logout occurred. No standard timed trial
account was created. Finalization receipt:
`C:\passkeys\worker106-tools\standard-winrm-finalization-summary.json`; detailed
inventory is `standard-winrm-preparation-inventory.json`. A fresh connection using
the committed checked client again proved elevated target identity.

Hypervisor `inspect` returned exit 1 with no output at 06:19:52 UTC after the
human's network/configuration changes. Its exact cause was not measured; do not
guess or loosen identity pins. Evidence is
`C:\passkeys\worker106-tools\standard-management-proxmox-inspect.json`. No power,
snapshot or rollback command was submitted after that refusal. No accessible
authenticated Proxmox browser tab was available for a UI fallback. Thus Windows
administration preparation is complete, but the verified stopped baseline remains
pending before application trials. Leave this working VM running.

## Canonical NIC repair and baseline, 2026-10-22 UTC

The operator provided an authenticated Proxmox browser session. Host web-shell
readback proved the deployed e964245d helper and the exact original UUID, disks,
name and MAC/bridge. The enabled NIC was serialized as
`net0: virtio=CC:34:21:7E:FE:59,bridge=vmbr0`, omitting the default link_down=0.
That exact equivalent form was missing from the helper's allowlist.

Fix source `ff1cb52f37645b465a4df2d75c2fb41230cc3f03` accepts only that third
representation and retains all other checks. Independent review found no
actionable findings; all 52 credential-free dispatch/identity checks and
governance verification passed. The host downloaded the immutable source,
verified SHA-256 `d9c13825a54dfa4bcc08c2a46450d8e593a534479b57fb20d299f83a8cedc43d`,
parsed it, and successfully inspected the actual configuration with the candidate.
Under the existing helper lock, it rechecked the old hash, preserved
`/usr/local/sbin/aiw-vm106.before-nic-fix-20261021`, and atomically installed the
root-owned mode-755 replacement. SSH keys were unchanged. Subsequent strict-key
SSH inspect succeeded.

Graceful shutdown returned 0 and stopped status was read back. At 07:05:23 UTC,
the fixed snapshot operation returned 0 and created logical-volume snapshots of
the OS, EFI and TPM disks named `aiw-vm106-baseline-20261021`. Stopped inspection
listed that baseline; separate host `qm config --snapshot` readback verified UUID,
MAC/bridge and disk identities with no vmstate entry. Proxmox's snapshots UI also
showed RAM No. Snapshot restoration was not exercised. The worker was then
restarted through the fixed helper; postboot administration is checked separately.

Postboot guest-agent readback confirmed the same NIC/IP and showed WinRM stopped
despite Automatic startup. A UUID-guarded guest-agent command started that existing
service. Standard encrypted WinRM then reconnected successfully and proved the
same guest UUID, administrator SID 1006 and elevated token. The reason it was
stopped after boot was not established; no startup-policy change or baseline
replacement was performed. The worker is left running and remotely manageable.

Controller evidence: `C:\passkeys\worker106-tools\nic-fix-live-inspect.json`,
`baseline-shutdown.json`, `baseline-create.json`, `baseline-stopped-inspect.json`,
`baseline-restart.json`, `baseline-postboot-winrm.json`, and
`baseline-proxmox.png`. No standard-user application trial began here.

## Integration storage-scope review, 2026-10-22

After the successful MSIX trial documented in VM106-MSIX-TRIALS.md, independent
integration review found that requiring the three pinned disks did not exclude
additional writable devices. Proxmox snapshots and rollback cover the full VM,
so an accidentally attached foreign volume would extend the operation's scope.

The shared current/snapshot configuration check now allowlists the exact OS, EFI
and TPM device lines plus only `ide2: none,media=cdrom`. It rejects any additional
IDE/SATA/SCSI/VirtIO/EFI/TPM/unused storage entry, occupied optical media, or
VirtIOFS host share. Negative dispatch controls cover both current/start and
snapshot/rollback configurations; all 70 dispatch/identity checks passed with
mock commands and no actual VM mutation. Independent review
of the narrow fix found no remaining issue. Source SHA-256:
`aafc3146148e2fb03f8f9cd62770cf2f0e8055f67b0222b62431b31a28e0e4e1`.
Live installation of this additional guard is pending; the existing baseline is
preserved and must not be replaced.
