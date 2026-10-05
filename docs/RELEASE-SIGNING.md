# Personal Artifact Signing

Nathan authorized this publisher/account on 2026-10-04 for this project's
signing and future public-release CI. Use his personal Artifact Signing identity;
do not substitute another publisher or create another signing account.

- Account resource: `/subscriptions/a80941e8-c2b9-4bc9-83ad-117cc40d0bea/resourceGroups/mvp-automation/providers/Microsoft.CodeSigning/codeSigningAccounts/asa-nathanmcnulty`.
- Endpoint: `https://wus2.codesigning.azure.net/`.
- Existing certificate profile: `kvpp-public-trust`, active `PublicTrust`.
- Expected certificate common name: `Nathan McNulty`.
- Signing action: `azure/artifact-signing-action@c7ab2a863ab5f9a846ddb8265964877ef296ee82`
  (resolved commit behind v2, not its annotated tag object).

## First bounded control

`artifact-signing-control.yml` is manual, owner-dispatched, main-only, and uses
the `artifact-signing` GitHub environment only for its signing job. Compilation,
signing, and signature verification run on separate disposable runners. The build
job has no signing identity or OIDC permission. The signing job checks the
transferred source/hash, signs only the fixed CLI output, and never runs build
code or the executable. Verification has no environment or OIDC authority;
it requires valid timestamped Authenticode with the expected publisher and retains
the exact signed bytes and verification record as an Actions artifact. This
control does not execute the CLI, install applications, or run Sandbox.

This is signing-path proof, not a signed desktop preview or a public-release
workflow. It does not edit or replace the accepted unsigned package, infer
application compatibility, or publish a release. Its workflow has no contents
write permission. The user-approved unsigned GitHub draft is separate.

## Authentication and threat boundary

Use a dedicated passwordless Entra application named `aiw-release-signing`.
Its federated credential is restricted to:

```text
issuer: https://token.actions.githubusercontent.com
subject: repo:nathanmcnulty@6653432/app-isolation-workbench@1340122842:environment:artifact-signing
audience: api://AzureADTokenExchange
```

Grant only `Artifact Signing Certificate Profile Signer`
(`2837e146-70d7-4cfd-ad55-7efa6464f958`) at the existing certificate-profile
resource, not account/subscription Owner, Contributor, or Identity Verifier.
The environment permits only branch `main`; workflow conditions also require
the canonical repository and owner actor. It never runs on PRs, forks, pushes,
or caller-supplied code/files. The public client ID belongs in environment
variable `AIW_SIGNING_CLIENT_ID`; no client secret/private key is generated.

Configuration was applied and read back on 2026-10-04: client ID
`2cf5967b-ebc6-431f-8ebd-3e221ef7e95e`, service principal
`085c0231-28b0-4437-81e4-cf71a847ebd2`, one exact-environment federated credential,
and one profile-scoped signer role. The environment's only deployment branch is
`main`. The retained host record is `%TEMP%\aiw-signing-configured-identity.json`.

Azure login uses OIDC and the explicit signing subscription. Artifact Signing
uses only that Azure CLI credential; environment, managed-identity, developer,
shared-cache, and interactive-browser alternatives are excluded. Never use
device-code authentication. Action dependencies have fixed versions in the
reviewed pinned action; its internal actions are also SHA-pinned.
Its dependency cache is disabled in the credentialed signing job so code run
during compilation cannot seed executable signing dependencies through a shared
repository cache.

The signature verifier holds the built file against concurrent write/delete,
records its hash and publisher/timestamp status, and writes a fresh result even
when the signature is rejected. An unsigned file was locally rejected with a
retained `NotSigned` record. The completed live control is recorded below.

## Completed live control

PR #84 merged at `210bbc995307e7a57455c10cbc557fed1633f727` after all three
CI checks passed at `5576576004bc71985cd4a7b44f46361650788040`; the merged tree
matched the tested tree. [Signing run 37247667778, attempt 2](https://github.com/nathanmcnulty/app-isolation-workbench/actions/runs/37247667778/attempts/2)
completed compilation, signing, and isolated verification successfully.

Attempt 1 retained an Azure federation rejection: this repository uses GitHub's
immutable owner/repository-ID subject, while the initial federation used the
older name-only subject. Read-only GitHub OIDC configuration confirmed the exact
prefix. The single existing Entra federation was corrected to the subject above,
read back, and only failed jobs were retried, reusing the successful build.
No permission expansion or client secret was needed. See [GitHub's subject
contract](https://docs.github.com/en/actions/reference/security/oidc).

The downloaded `aiw-signing-control-210bbc995307e7a57455c10cbc557fed1633f727`
artifact contains the 13,423,888-byte signed `aiw.exe`. Independent host verification
agreed with the runner record:

- Signed SHA-256: `8c7e9e73fd6fea2747ae3fccdadda70e46ce7e8d9d0b9f8b27d2c0f0af2ef616`.
- Authenticode status: `Valid`; publisher: `Nathan McNulty`; timestamp present.
- A separate copy changed at byte offset 4096 was rejected with `HashMismatch`;
  the original retained binary was preserved.
- Local evidence: `%TEMP%\AIW-Signing-Control-210bbc9`, including runner,
  independent, and tamper verification records. Failed-attempt logs and the
  corrected federation readback are retained separately under `%TEMP%`.

Actions artifacts expire after 14 days; the downloaded host evidence is the
retained local copy. This proves the personal signing path for this CLI control,
not signed desktop assembly, runtime acceptance, or public distribution.

## Moving from control to release

Nathan authorized the following order on 2026-10-04, once a good public candidate
is ready:

1. Finish the signed desktop assembly path and resolve candidate-blocking findings.
2. Review the exact release CI for build/signing separation, token permissions,
   pinned actions, source/artifact binding, and public PR/fork behavior. Check
   repository contents and history for material that must remain private before
   changing visibility.
3. Make the repository public, then use reviewed CI to build, sign, assemble,
   and publish the candidate from the exact approved source revision.
4. Download those published artifacts, independently verify their identities and
   publisher signatures, and test the exact download on the dedicated supported
   VM. Supply copy-and-paste operator commands and fresh evidence destinations
   whenever human participation is needed.
5. Publish the first candidate as an alpha/prerelease; promote a stable release
   only after its downloaded-artifact acceptance is recorded.

This is conditional authorization for that sequence, not a declaration that the
current unsigned draft is ready or that its historical trials validate newly
signed bytes. CI-built downloadable candidates precede final distribution
acceptance; stable-release claims follow that acceptance.

Sign final executables/scripts **before** calculating manifests, guest identity,
receipts, and archive hashes. Signature bytes change SHA-256; signing an existing
receipt-bound package in place invalidates its evidence bindings. Signed guest
bytes require fresh preparation/approval and appropriate disposable-worker proof;
do not relabel historical unsigned runs as signed-candidate acceptance.

Public distribution needs a complete signed candidate and fresh identity-bound
acceptance. Keep the exact original package and evidence readable. This account
selection and the signing control do not alone close those release gates.
