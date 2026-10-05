# First public alpha: CI and visibility review

Independent review completed for the optional publication job on top of merged candidate
assembly `0cb8cad6605b857170a199e28f9f9a3577defd05`. Repository visibility remains
private. Independent exact-commit review, hosted CI, and the full private signed
candidate result are gates before the authorized public transition.

## Checks completed

- Independent review of `5f85a7f8a53dedbf068162533f5efffce6eda322`, with the
  README follow-up at `9d7bd47`, found no actionable findings. It covered job
  authority, same-run asset binding, draft publication, provenance, action pins,
  Windows glob handling, and public fork permissions.
- Full private signed control run `37250759217` passed build, signing, and
  assembly at `0cb8cad6605b857170a199e28f9f9a3577defd05`. Independent download
  and extraction verified the timestamped personal publisher on both handoff
  scripts and all six fixed package paths, closed inventory, exact source and
  receipt. ZIP SHA-256 is
  `4a4726183401b0b65b7f6d4f3adcf6ef3fe2f5aede90e7043ef6c2ed5fd1a0c8`;
  receipt SHA-256 is
  `04cb4d4777e8aaa5c9c2f3437dbdf9ada836797bf1e12864ce61eb58bc6357f9`.
  Local evidence root is recorded in `%TEMP%\aiw-signed-desktop-proof-root.txt`.
  No candidate application ran on the host; runtime acceptance remains open.

- `actionlint` 1.7.12 accepted all three repository workflows. Its Windows release
  ZIP was verified against upstream GitHub asset SHA-256
  `6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9`.
- `gitleaks` 8.30.1 scanned all local refs with full history and merge-parent diffs:
  459 commits, approximately 11.92 MB, no findings. Its tool ZIP matched upstream
  SHA-256 `d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e`.
  Reports are redacted. This is a scanner result, not a guarantee that every
  possible confidential datum is detectable. Current tracked binary inventory
  contains only the desktop icon; installers, private keys, and live evidence are
  not committed. Refresh the scan at the final transition head.
- GitHub default workflow permission is read-only; workflow tokens cannot approve
  PR reviews. All three workflows explicitly default to contents-read. Governance
  now checks full-SHA action pins in every workflow, including inline step syntax.
- The `artifact-signing` environment allows only main. The dedicated passwordless
  identity is restricted to the immutable repository/environment subject and
  existing certificate-profile signer role, as recorded in RELEASE-SIGNING.
- A separate `public-release` environment was configured and read back with one
  deployment policy: branch main. It has no Azure federation or signing secret.
- The open `glib` advisory GHSA-wrw7-89jp-8q8g is in the desktop lockfile's
  non-Windows dependency graph. `cargo tree --locked --target
  x86_64-pc-windows-msvc -i glib` found no dependency path. The Windows-only alpha
  does not ship that crate; the advisory remains visible rather than being
  dismissed or presented as repaired. Hosted dependency audit still must pass.

Local review-tool evidence is under the directory recorded in
`%TEMP%\aiw-release-review-tools.json`. Source/signature/hash controls and their
limits are in [RELEASE-SIGNING.md](RELEASE-SIGNING.md).

## Authority and publication boundary

Compilation has no environment or OIDC authority. Signing consumes only five
fixed hash-checked files, never checks out/builds/runs project code, disables
executable dependency caches, and uses only the profile-scoped Azure CLI login.
Assembly has no OIDC and checks signatures before executing handoff scripts;
it binds signed guest bytes into fresh manifests/receipt and round-trips the ZIP.

Publication is an explicit false-by-default input, owner-dispatched on main in
the public canonical repository. Only the separate publication job can write
release contents or attestations. It executes no candidate binary/script, checks
same-run assembly hashes, attests each downloadable file, verifies draft asset
digests, and exposes only an alpha prerelease. It refuses existing tags and
retains partial drafts on failure. No generic caller-supplied URL, code, tag,
source revision, or files are accepted.

Public PR/fork CI runs with read-only permissions and no signing/release environment.
Manual release workflows cannot be reached from pull_request, pull_request_target,
workflow_run, or a public reusable workflow caller. SHA pins and cache isolation
reduce dependency substitution risk; reviewed main source and pinned third-party
actions remain trusted. Main currently has no enforced branch protection:
integration requires exact-head review/check success and matched merged trees;
this review does not change repository-required checks or imply their enforcement.

## Remaining acceptance

1. Review is complete; require all three CI jobs on the final PR head.
2. Verify the merged main tree matches the tested PR tree.
3. Retain/download the full signed private control and check source, signatures,
   receipt, ZIP identities, and extraction. Its runtime acceptance remains separate.
4. Recheck final public-exposure scan and environment/federation identities; then
   make the repository public under Nathan's conditional authorization.
5. Dispatch public CI with publication explicitly requested. Verify public release
   status, exact tag source, five assets/digests, and build provenance.
6. Download the public assets into a fresh folder and verify/test those exact bytes
   on the dedicated supported VM. Do not substitute private build or historical
   unsigned acceptance. Keep stable promotion gated on that evidence.

## Public transition and draft API correction

PR #86 merged at `90d06e7fe223bfe1166bd996f0e1db8c3a068be4` after all three
CI jobs passed at `40c9df8` (run `37252512658`). Its merged tree matches the tested
PR tree. Final scan covered 463 commits with no findings. The authorized public
transition was read back anonymously; the immutable OIDC subject was unchanged.

Before publication, a read-only API control against the existing unsigned draft
found a release lookup defect missed by the initial review: authenticated
`GET /releases/tags/desktop-preview-e08115b` returns 404 for the draft, whereas
paginated `GET /releases` resolves numeric ID `403260000` and `GET /releases/403260000`
returns its exact tag, source, draft state and five assets. Public workflow run
`37253486994` was canceled during compilation, before signing or publication.
No public alpha or new draft was created.

Publication now resolves exactly one numeric ID for the fixed tag from the
paginated release list, then reads that ID and applies the existing draft/source/
asset digest checks. Missing or ambiguous identity refuses publication and
preserves the draft. The published-release readback still uses its published tag.
The existing unsigned draft was only read and remains unchanged. This correction
requires independent review and exact-head hosted CI before the next dispatch.
