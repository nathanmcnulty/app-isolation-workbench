# MXC first-party creation trial, 2026-11-06

This is a partial research result, not application compatibility or effective
isolation acceptance. Source `55068e6088eac18f5b44e8e3b8232d177dc62eb6`
dispatched the fixed cooperative Driver control in one fresh Windows Sandbox on
existing VM107. No vendor application ran. The existing user authorization covered
the pinned Microsoft MXC 1.0.1 runtime only inside fresh Sandboxes; no parent
runtime installation, VM configuration or host security change occurred.

## Observed outcome

All five ordinary filesystem positives passed before dispatch: Input and Denied
content reads, nonmutating Input write/delete access opens, and Output write/read.
The exact Driver probe reported `supportedForRequest`, native base-container tier,
no DACL fallback or BFS and no warnings. These are capability reports.

The SDK spawn call returned status `0`, a handle and PID `6580`. The ordinary
held-process observer then refused with `fixed ordinary MXC child primary token
differs`. This combined guard checked schema, PID, SID, primary token type,
elevation and AppContainer flag before retaining the token. Actual token values
and the individual failing predicate were therefore lost. Neither an
AppContainer flag value nor any other mismatch cause can be inferred.

BOUND, READY, owner child observation and candidate controls were absent. The
protected release gate stayed closed. Candidate enforcement, selected-tier
attestation and 7-Zip compatibility remain unmeasured; this result does not
establish MXC unavailability or fallback. SDK free began and returned; that alone
does not prove the SDK's inner job empty. The owned worker job and outer Sandbox
cleanup were independently verified. Original marker bytes stayed stable across
cleanup, and retained Read matched with zero provider calls.

## Source and evidence binding

Private originals and audit proofs remain outside Git under
`C:/aiw/mxc-multimode-20261106/`. Do not repair, adopt or replay this trial.

| Item | SHA-256 |
|---|---|
| `mxc-creation-55068e6-r1.zip`, 3,807,282 bytes | `e092b025a692ae1f9cade503fbf2579c1104984affee11b0431071d4fa653718` |
| Frozen helper, 992,768 bytes | `5d72d2f805bb384793fff59318d2ec7318bcf4158eb54d8991334518271c6e51` |
| Pinned Microsoft runtime, 6,123,320 bytes | `bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c` |
| Approved plan | `fbcdc38d57b19af5a8b1245a62f9d6a23250a5d4a9f78a9fdbc2693f40a28d0c` |
| Exact Driver request | `c7e29c1e6411a5b122018a921e0e601d7f8f9df2994b51e732183a6077f77d78` |
| Start received envelope | `40707668005fefdaf6bf5a45272bf534935b1a095f4c78f2b78679d9817d3d0a` |
| Read received envelope | `eb60a0c6d1308af1b9f4800778475556612708bda0c00b0a5151741c0158a821` |
| Original guest marker, 5,840 bytes | `8a38043203489710b34f7d072a7d9f54fc9e1226b1f78d329a61bdf9864db0b2` |
| Independent outcome audit | `7489b6e73e63428f1b7e8daa7006d7ffd9f1743069cca54b04701ed56d8db3f7` |

The independent audit losslessly bound source, proposal, approval, intent,
configuration, Start, retained host result, cleanup and Read. It reconstructed
and hashed the original guest bytes and retained them with create-new semantics.
Exactly six of the sixteen phase prefixes were present: baseline, probe,
spawnCall, spawn, freeBegin and freeEnd. The ten others had explicit missing-file
errors. Host Start exit `0` describes custody and cleanup completion, not a
successful candidate control.

## Observer correction

Source `9093182` retains the full measured root token and individual identity
validation errors before refusal. Only the exact fixed contained root accepts
either measured AppContainer flag; the ordinary worker still requires false.
SID, primary type, unelevated state, PID/schema, held image/time/token agreement,
request binding and exact outer-job membership remain required before release.
No policy, DACL fallback or permissions are widened. The flag is a measured token
property, not MXC backend provenance. The separately reviewed fresh trial below
does not retroactively validate the previous run. See the
[acceptance map](MULTIMODE-ASSESSMENT.md) for the remaining full scope.

## Fresh token-observer trial at `9093182`

The separately reviewed package at source
`9093182b688c4ff9cfce016d735296007f09c388` ran once in another fresh Sandbox.
Prepare and exact-plan approval completed separately. The fixed policy and
runtime were unchanged; the root/session and payload identities were fresh.

Ordinary positives passed. SDK spawn returned status `0` and PID `6596`. The
ordinary worker and elevated owner retained identical full child observations:
held image bytes, creation time and actual primary token. Both token validation
error lists were empty, exact outer-job membership passed, and the protected
owner gate was published. The observed token had the standard user's SID,
`isAppContainer=true`, low integrity RID `4096`, unelevated state and one
capability SID with attributes `4`. These are actual token properties; they do
not attest the selected backend or explain the previous trial's unknown token
mismatch.

No SELF, CONTROL or contained FAILURE record appeared. The ordinary worker
reached its 30-second caller deadline and retained timeout-kill status `0` and
SDK free begin/return. Owner post-exit revalidation retained
`QueryFullProcessImageNameW` HRESULT `0x8007001f` after termination. Earlier
successful owner/job/gate evidence survived that failure. Twelve of eighteen
prefixes were present; six had explicit missing-file errors. Candidate
filesystem enforcement, clean SDK completion, inner SDK job emptiness,
selected-tier attestation and application compatibility remain unmeasured.

Owned worker and outer Sandbox cleanup passed. Marker bytes stayed stable across
cleanup; retained Read matched with zero provider calls. No recovery was needed.
Both packages/runs remain preserved, including original guest bytes reconstructed
losslessly by an independent audit. No parent runtime or VM settings changed.

| Item | SHA-256 |
|---|---|
| `mxc-creation-9093182-r1.zip`, 3,815,326 bytes | `4859f7ce4caca2c978812e79d542f7649b9f7e42b0c10e88c8adba170d3797c7` |
| Helper, 1,009,152 bytes | `1533a92f346e20bf4e202a72f26db39298ac4d49f79e0f9d1aa03aea5767b64b` |
| Approved plan | `3b5ec4182770277cd4bbe642532896060075bc790be1cd58e1a697cbd3768f74` |
| Rendered config | `1e24dd34758c42087c8c92353e094ea9c3c9a72c7ac1e0d3122683b3c8574835` |
| Start received envelope | `6b44a8f94d16ae23d62762644d021c5e959487127d39eac4f237097937945d23` |
| Read received envelope | `1e1317b75648258272da5d0223986b66c7cff2b305230993a7099691108e70ae` |
| Original guest marker, 11,105 bytes | `524b412eecc32f86a99993c7923df3f161f8d3aadd704bd03ae3a7bcee726469` |
| Independent outcome audit | `b5895178dfc16052f6bee2df289f6662e974c2002ab62b94bed2baa100509c31` |

## Contained entry correction, native acceptance pending

Before SELF publication, the contained role previously queried Windows through
WinRT `AnalyticsInfo` and resolved the account with `LookupAccountNameW`. Either
may be unnecessary inside the restricted child; neither is established as the
timeout's cause. Missing SELF also cannot exclude loader, Rust startup, argument/
image retrieval, token-query or publication failures.

The next correction routes only the exact contained image/arguments to an early
ENTRY record, then actual SELF token diagnostics. These writes precede token and
environment authorization and never authorize controls. Setup and the ordinary
worker retain exact Windows/account checks before SDK dispatch. The contained
role delegates environment/actor authorization to their verified owner chain and
must match the protected gate's full token, PID, creation time, helper and request
hashes. It no longer repeats WinRT activation or account-name lookup inside PSEC.
Missing or mismatched gates still refuse controls; policy, grants, deadlines and
owned cleanup remain unchanged. This needs another separately reviewed fresh
package/trial and does not retroactively validate either earlier run.
