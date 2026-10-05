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
subject: repo:nathanmcnulty/app-isolation-workbench:environment:artifact-signing
audience: api://AzureADTokenExchange
```

Grant only `Artifact Signing Certificate Profile Signer`
(`2837e146-70d7-4cfd-ad55-7efa6464f958`) at the existing certificate-profile
resource, not account/subscription Owner, Contributor, or Identity Verifier.
The environment permits only branch `main`; workflow conditions also require
the canonical repository and owner actor. It never runs on PRs, forks, pushes,
or caller-supplied code/files. The public client ID belongs in environment
variable `AIW_SIGNING_CLIENT_ID`; no client secret/private key is generated.

Azure login uses OIDC and the explicit signing subscription. Artifact Signing
uses only that Azure CLI credential; environment, managed-identity, developer,
shared-cache, and interactive-browser alternatives are excluded. Never use
device-code authentication. Action dependencies have fixed versions in the
reviewed pinned action; its internal actions are also SHA-pinned.

The signature verifier holds the built file against concurrent write/delete,
records its hash and publisher/timestamp status, and writes a fresh result even
when the signature is rejected. An unsigned file was locally rejected with a
retained `NotSigned` record. Live signing remains unproven until the exact
merged workflow completes and its retained artifact is independently verified.

## Moving from control to release

Sign final executables/scripts **before** calculating manifests, guest identity,
receipts, and archive hashes. Signature bytes change SHA-256; signing an existing
receipt-bound package in place invalidates its evidence bindings. Signed guest
bytes require fresh preparation/approval and appropriate disposable-worker proof;
do not relabel historical unsigned runs as signed-candidate acceptance.

Public distribution needs a complete signed candidate and fresh identity-bound
acceptance. Keep the exact original package and evidence readable. This account
selection and the signing control do not alone close those release gates.
