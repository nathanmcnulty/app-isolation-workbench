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

The next source retains the full measured root token and individual identity
validation errors before refusal. Only the exact fixed contained root accepts
either measured AppContainer flag; the ordinary worker still requires false.
SID, primary type, unelevated state, PID/schema, held image/time/token agreement,
request binding and exact outer-job membership remain required before release.
No policy, DACL fallback or permissions are widened. The flag is a measured token
property, not MXC backend provenance. This correction requires a separately
reviewed fresh package and native trial; it does not retroactively validate this
run. See the [acceptance map](MULTIMODE-ASSESSMENT.md) for the remaining full scope.
