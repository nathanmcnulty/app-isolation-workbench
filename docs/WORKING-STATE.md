# Working state

Updated 2026-11-05 (America/Anchorage). Checkout `C:\aiw\app-isolation-workbench`,
branch `codex/real-app-assessment`; current source `593281a` follows production
integration `614bb0e`.
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
observations, not production receipts. The separate desktop application path is
implemented at `614bb0e`; its native acceptance remains open.
Independent consequential review fixes are complete, including the separately
reviewed fixed VM107 staging wrapper's held ancestry/executable custody.

Offline checks passed: six focused platform tests; two host marker/recovery tests;
feature-enabled all-target Clippy with warnings denied; format/governance; static
CRT x64 release builds. Logs `C:/aiw/sevenzip-final-platform-tests.log`,
`sevenzip-host-tests.log`, `sevenzip-final-clippy.log`, `sevenzip-final-governance.log`,
`sevenzip-static-helper-build.log`, `sevenzip-static-host-build.log`.
Wrapper native custody compiled and five inert checks passed; see the private audit.

## Native research completed; production integration in progress

Private audit/package: `C:/aiw/sevenzip-assessment-20261105`.
`Package/Trial.ps1` supports separate fixed Prepare/Approve/Start/Recover/Read;
`package-pins.json`, `archive-pins.json`, `provenance.json`,
`wrapper-custody-tests.json`, `access-readback.json` retain exact local observations.
The inert archive `sevenzip-trial-b7f17cf.zip` is 2,486,236 bytes, SHA-256
`3afefbc7ae241d02a697c1a77ab0bf84f8e4b20fc3303f308ec2902ac006bfa9`.
Target package directory is `C:\AIW-SevenZip-Trial-20261105` on **VM107 only**.
The verified package was staged there and executed once after separate approval.

The original Proxmox console was restored without changing security settings.
Bounded clipboard parts reconstructed the exact pinned package. Fresh readback
verified UUID107, Core7.6.9, nonadmin `AIW\labadmin`, session1. The actual prepared
proposal was independently reviewed, approved by exact hash, and started once.
Installation and create/test/extract/content verification succeeded in both modes.
Selected access-denied canaries, held target tokens, profile deletion, empty jobs
and outer cleanup were observed. See [native acceptance](SEVENZIP-NATIVE-ACCEPTANCE.md).
Research records remain separate from production Results. No retry was needed.

A fresh normal TLS handshake to `192.168.1.174:5986` failed `NotTimeValid` without
sending credentials. Enrolled certificate `BC14DCC4E37F83161EBB55AF8624E36A79E19256`
expired `2026-11-05T08:49:10Z`. No TLS bypass, certificate renewal, firewall,
network, authentication, VM or other security-setting change was made.
Browser console access supplies the working route; no user access change is now
required. No TLS bypass was used. The bounded readback receiver closed after
retaining the exact archive. Preserve all transfer, trial and audit artifacts.

## Preserve the completed milestone

PR #105 is merged. VM107 run `paired-1793931286787802700` completed all six fixed
controls with exact cleanup; source53ed corrected Results exports were deterministic,
preserved all29 retained files, and made zero reader execution/provider calls.
Reuse the [native record](PAIRED-NATIVE-APPROVAL.md),
[acceptance audit](RESULTS-ACCEPTANCE-AUDIT.md) and
[Results documentation](RESULTS-EXPLORER.md). Original audit:
`C:/aiw/paired-directory-sharing-native-65b084f3-5d85-4dda-83a1-12754bbda14f`.
Preserve VM106, every old package/run, accidental `C:\Evidence` and unrelated work.

Integration adds a closed 7-Zip profile/action, protected installer
intake and role copies, receipt-bound native guest facts, retained comparison,
sanitized Results projection and desktop approval/Start/cancel/recovery entry.
Checks pass: eight profile/provider tests, nine guest/platform driver tests, ten
approval/preparation/service/retained-reader tests, two desktop controller/projection
tests, focused root and desktop all-target Clippy, format/governance, and seven
inert package-verifier controls. Static release builds and the follow-up package
verification pass; production native proof remains pending. Research ZIPs
cannot enter verified production Results.

The exact nine-file `614bb0e` product package was staged and verified on VM107.
Desktop Prepare, independently reviewed plan, exact-hash Approve and single Start
completed for `sevenzip-1793950517554284900`. The product retained
`DriverIncomplete` with verified outer cleanup; all application functions remain
unmeasured. Its old fallback discarded the cause. Preserve the old package,
workspace, review and approval; do not Start it again. See
[native acceptance](SEVENZIP-NATIVE-ACCEPTANCE.md). This is not incompatibility.

Follow-up source adds bounded private receipt-bound diagnostics and same-fixed-path
Windows spelling handling. Focused tests and independent consequential review pass;
static rebuild passes; fresh native validation is in progress. The old failure's
cause is unknown. Worker console access recovered after a temporary browser
disconnection; no security settings changed. The completed desktop was closed;
its retained package and evidence remain on VM107.

The incomplete run was reopened in actual Results and exported as sanitized JSON
with all 26 retained files unchanged; the [native record](SEVENZIP-NATIVE-ACCEPTANCE.md)
retains its size/hash and scope. No reader execution/provider call occurred.

The rebuilt `593281a` package is verified. Transfer to VM107 is in progress with
41 of 42 parts acknowledged at this update. The receiver deadline expired while
the final clipboard value was not delivered; all originals were preserved and
verified by a bounded data-only resume helper. A smaller-fragment final-part
resume is being prepared. No new application trial has run.
Next: complete and verify that transfer, then validate a fresh separately approved
production plan. Preserve the original failure and approval without another Start.
The requested full application flow, Benchmark 2, W4/W5 and production acceptance
remain **open**; see the [criteria mapping](SEVENZIP-ASSESSMENT.md#coverage-limits-and-acceptance).
