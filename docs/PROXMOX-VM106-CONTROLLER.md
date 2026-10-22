# VM 106 isolated worker controller

This is a research setup boundary for the Proxmox clone `passkeys-worker`, not application acceptance. The operator confirmed it is stopped, has a new MAC and disconnected network, and has automatic start disabled. Keep the original PASSKEYS VM as the controller.

## Source and authority

The source helper is preserved at commit `61a531708633cda4dad9708e5ff1af887072d541`, SHA-256 `7a6454f5478f2a89cfa034e962818a39e8d0a50db80cbb28acfff9ea0c1c006c`. Its tree matches locally reviewed commit `3e9065a7282e19e5b3b08d647f1902ea3a5edea2`. Publication used the connected GitHub integration because GitHub CLI credentials had expired. The source was downloaded again and its hash verified.

The helper pins host `pve-r630`, VM 106, name `passkeys-worker`, SMBIOS UUID `7e686bee-8c05-43c7-9603-a9562ece224c`, EFI/OS/TPM disks on `r630-fast2`, `net0` MAC `CC:34:21:7E:FE:59` with `link_down=1`, `onboot=0` and the guest agent. It rejects pending configuration changes, additional network adapters, arbitrary QEMU arguments, PCI/USB passthrough and host hooks.

Only exact SSH command strings `inspect`, `status`, `shutdown`, `start`, `snapshot` and `rollback` are accepted. No caller arguments, shell evaluation, clone, guest execution, network changes, snapshot deletion or arbitrary target selection exists. Baseline `aiw-vm106-baseline-20261021` creation requires stopped state and records no memory. An existing baseline cannot be replaced. Rollback requires stopped state and matching snapshot identity/disconnected configuration; memory-state snapshots are rejected.

The root-owned lock serializes this helper's calls, not independent administrators or automation. Avoid concurrent out-of-band configuration changes. Root-owned helper/key files, normal SSH environment restrictions and protected snapshot custody remain deployment assumptions. This does not measure application compatibility or effective isolation.

## One operator step

Run [install-proxmox-vm106.sh](../scripts/research/install-proxmox-vm106.sh) once in the **root shell on pve-r630**. It downloads the immutable helper, checks its independent hash and syntax, and performs read-only identity/storage inspection before installation. It refuses an existing helper or a symlinked `/root/.ssh` directory. A symlinked `authorized_keys` is accepted only when its canonical target is the existing root-owned mode-600 `/etc/pve/priv/authorized_keys`; other targets are rejected. The Proxmox-managed target is appended to without changing its ownership or permissions. This managed file is cluster-shared; the key's forced command still pins the host and VM, and no helper is deployed to other nodes. An ordinary regular `authorized_keys` file is also supported. The installer writes `/usr/local/sbin/aiw-vm106` root-owned mode 755 and appends the dedicated public key with `restrict,command="/usr/local/sbin/aiw-vm106"`. The private key remains on the controller and was generated after cloning.

Expected completion: configuration/status/snapshot/storage output, then `Installed restricted VM 106 helper; worker remains stopped and disconnected.` and the helper hash above. On error, preserve output; do not weaken checks or overwrite an existing helper. No worker boot, snapshot or rollback is part of installation.

The controller's local `C:\passkeys\worker106-tools\ssh_config` pins the operator-verified Ed25519 host fingerprint `SHA256:J/kc0UwUBil5TFBQbQhwBoRKnDoRlZ8ggXAhmYEpq1E`, uses its dedicated key, disables interactive fallback/forwarding, and requires strict host-key checks. The first live call after installation will be read-only `inspect`.

## Validation and next step

36 credential-free mocked dispatch/identity checks passed, including command injection, caller arguments, wrong host/root/VM fields, pending config, alternate networking, running-worker snapshot/rollback, snapshot drift, memory state and missing baseline. Shell parsing and governance checks passed. Independent review found one alternate-network-path issue in the initial source; the final helper resolved it and had no remaining actionable findings. Mocks do not prove Linux flock behavior or live Proxmox mutation semantics. No guest operation has run through this helper yet.

After live read-only inspection, prepare Windows identity/auth-state cleanup and separate worker access. Do not start copied Codex/Tailscale sessions or adopt browser/GitHub/Azure caches. Arrange real standard-user login before a time-limited window. Rebind and independently review the historical Azure-pinned driver/controllers for the actual worker. Before allowing network changes, review a new exact network binding; this initial helper deliberately rejects connected-network configurations. Take the actual baseline only after worker preparation, then prove the fixed Scheduler WTS control before the signed MSIX lifecycle. Export evidence to the controller before rollback. Provider Hello/Key Vault/RP trials remain separate.
