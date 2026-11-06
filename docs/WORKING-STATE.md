# Working state

Updated 2026-11-05 (America/Anchorage). Checkout `C:\aiw\app-isolation-workbench`,
branch `codex/real-app-assessment`, source `b7f17cfab74ebb98ebda6687643267c18de9b002`.
Started from current main `8aeeafc` including merged PR #105. Working branch has not
been pushed or published. Start with `scripts/work-status.ps1`.

## Active real-application assessment

Selected **7-Zip 26.05 x64, install/create/test/extract/verify**, ordinary standard
user versus classic AppContainer with zero capabilities inside a disposable
Sandbox on VM107. [Declared workflow](SEVENZIP-ASSESSMENT.md) records provenance,
measurements and gaps. [MXC selection](MXC-ASSESSMENT-SELECTION.md) separately pins
current release/main research across all four families; the old planning adapter
has not advanced. MSIX alone and the outer Sandbox are not isolation proof.

Source b7f17cf adds default-off `research-sevenzip` guest and host examples, fixed
mapped-input custody with strict local execution custody, process-driver controls
before install, held app tokens, exact inventory/content verification, protected
input/write/delete and outside-grant canaries, durable atomic stages, separate
Prepare/Approve/Start and original-session cleanup/recovery. These are research
observations, not production receipts or an implemented desktop application path.
Independent consequential review fixes are complete, including the separately
reviewed fixed VM107 staging wrapper's held ancestry/executable custody.

Offline checks passed: six focused platform tests; two host marker/recovery tests;
feature-enabled all-target Clippy with warnings denied; format/governance; static
CRT x64 release builds. Logs `C:/aiw/sevenzip-final-platform-tests.log`,
`sevenzip-host-tests.log`, `sevenzip-final-clippy.log`, `sevenzip-final-governance.log`,
`sevenzip-static-helper-build.log`, `sevenzip-static-host-build.log`.
Wrapper native custody compiled and five inert checks passed; see the private audit.

## Native access blocker — no application executed

Private audit/package: `C:/aiw/sevenzip-assessment-20261105`.
`Package/Trial.ps1` supports separate fixed Prepare/Approve/Start/Recover/Read;
`package-pins.json`, `archive-pins.json`, `provenance.json`,
`wrapper-custody-tests.json`, `access-readback.json` retain exact local observations.
The inert archive `sevenzip-trial-b7f17cf.zip` is 2,486,236 bytes, SHA-256
`3afefbc7ae241d02a697c1a77ab0bf84f8e4b20fc3303f308ec2902ac006bfa9`.
Target package directory is `C:\AIW-SevenZip-Trial-20261105` on **VM107 only**.
Do not infer successful staging from this proposed destination.

Fresh console readback verified UUID107, Core7.6.9, nonadmin `AIW\labadmin`, session1.
The direct transfer failed before creating its destination. A large clipboard
message disconnected the browser bridge; its restored connection had unreliable
clipboard/key input. No numbered-parts receiver was executed. The final guest
screen showed a clean prompt after reverting only our unexecuted input. No native
helper/host EXE, installer, application, provider, approval or Start ran for this
slice. Both temporary delivery servers are stopped. The owned trial console tab
closed; cleanup of the local artifact browser tab could not be verified after a
debugger error. The user's original Proxmox tab was preserved.

A fresh normal TLS handshake to `192.168.1.174:5986` failed `NotTimeValid` without
sending credentials. Enrolled certificate `BC14DCC4E37F83161EBB55AF8624E36A79E19256`
expired `2026-11-05T08:49:10Z`. No TLS bypass, certificate renewal, firewall,
network, authentication, VM or other security-setting change was made.
User input is pending: reconnect Edge computer control or restore the existing
trusted VM107 remoting route. On restoration, recheck identity and destination
absence, stage the independently pinned archive, run **Prepare only**, inspect its
actual typed proposal, and then use separate exact approval and Start. Do not guess
plan hashes, repeat an old run, or treat transfer/driver failure as incompatibility.

## Preserve the completed milestone

PR #105 is merged. VM107 run `paired-1793931286787802700` completed all six fixed
controls with exact cleanup; source53ed corrected Results exports were deterministic,
preserved all29 retained files, and made zero reader execution/provider calls.
Reuse the [native record](PAIRED-NATIVE-APPROVAL.md),
[acceptance audit](RESULTS-ACCEPTANCE-AUDIT.md) and
[Results documentation](RESULTS-EXPLORER.md). Original audit:
`C:/aiw/paired-directory-sharing-native-65b084f3-5d85-4dda-83a1-12754bbda14f`.
Preserve VM106, every old package/run, accidental `C:\Evidence` and unrelated work.

Next after feasibility: production preparation/approval/session integration,
cancellation/recovery, verified retained comparison and sanitized Results export,
desktop entry, native validation and review. The requested full application flow,
Benchmark2, W4/W5 and production acceptance remain **open**.
