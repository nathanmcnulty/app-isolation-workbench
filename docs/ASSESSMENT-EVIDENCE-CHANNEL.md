# Assessment evidence channel

Design and acceptance requirements. The implementation is under consequential
source review and is **not natively qualified**. Dispatch must remain refused
whenever a collector guard fails. This document grants no execution authority.

## Observed boundary failure

The source-71d1877 ordinary control on the 114 Sandbox CLI completed its owned
outer lifecycle and cleanup, but dispatched no application. Under the fresh
standard user, 13 of 15 individual mutation-access opens against the mapped
collector succeeded, one returned access denied 5, and one returned sharing
error 32. The last result is unknown, not a security denial. The retained
outcome is insufficient evidence / not run. Public hashes and evidence chains
check consistency; they do not authenticate a candidate-writable mapped folder.

Moving collection locally and then copying a receipt is insufficient: a
candidate can forge a mapped completion before the real collector finishes.
The parent must authenticate transport before allowing it to settle a run.

## Chosen boundary

Use protected guest-local collection and a per-run signed channel over the
existing mapped output. Keep the current four mappings and provider verbs.
Do not change host ACLs, install a runtime, widen application grants, or fall
back to a weaker worker. A fixed System exec digest is an alternative requiring
new approved verbs and native wire qualification; it is not an existing adapter
capability. The documented CLI returns exit status but offers no process I/O.

Fresh generic plans must explicitly approve a new channel version, fixed
algorithm, paths, budgets, and Start-time key/nonce generation. Existing v1/v2
plans and approvals retain their original hashes and cannot acquire this
authority. Request and transaction schemas must version the new fields rather
than silently extending historical execution.

1. Under the owned run lock and one-shot Start intent, generate an ephemeral
   host ACK signing key and a fresh 32-byte CSPRNG nonce. Persist an immutable
   **public** execution descriptor and complete request outside every guest
   mapping before provider invocation. Bind the approved plan, request,
   assessment, code, provider/protocol, configuration, workspace and session.
   No private key enters a file, environment, command line, log or mapping.
2. The fixed elevated agent creates a fresh local collector outside mapped
   targets before creating progress or the standard account. Hold ordinary
   file identities and no-follow ancestry; never adopt an existing directory.
   Preserve all 15 independent native denial-5 probes against the local
   collector/progress, including broad sharing during the probes. Any success,
   sharing error, missing observation or impersonation failure blocks dispatch.
3. Generate the guest signing key in collector memory. Publish a bounded public
   bootstrap bound to the full request and nonce. Before any application
   creation, the host latches this guest key exactly once in protected run
   records, signs an ACK binding both keys and the bootstrap digest, and
   durably records it before publishing it. Destroy the host private handle
   before publishing this single ACK. The agent verifies the ACK against the
   host public key in its read-only request. The ACK acknowledges the collector
   key; it does not grant application dispatch. Account setup and native file,
   process/thread and primary-token default-DACL guards follow, permitting a
   signed setup failure. Every guard must pass before any application creation.
4. Sign bounded progress commitments and one terminal manifest. Commit to the
   exact payload bytes, byte length, record type, sequence, previous canonical
   content commitment and complete execution binding. The terminal binds every
   fixed artifact's exact name, length and SHA-256, the raw receipt, evidence
   root and final progress commitment. Preserve actual failure/cleanup facts;
   signing a failure does not turn it into a successful assessment.
5. Generic waiting accepts only authenticated records under the persisted
   latched key. File existence, matching public hashes, self-reported keys or
   a guest failure filename cannot settle the run. Revalidate held artifact
   bytes before interpretation. Exact-session stop/reconciliation remains an
   independent parent responsibility.

## Wire and key boundary

Use Windows CNG ECDSA P-256 with SHA-256, finalized ephemeral key handles and
public-only export/import. Use a fixed 72-byte `BCRYPT_ECCPUBLIC_BLOB` with
`ECS1` magic and 32-byte coordinates, and fixed 64-byte raw `r || s` signatures,
encoded as lowercase hex. Import with validation enabled; reject malformed
points/encodings rather than implementing elliptic-curve math. Sign a fixed
domain-separated digest of closed typed DTOs using the existing integer-only
canonical JSON routine. Reject unknown/duplicate fields and alternate schemas;
preserve exact u64 values. Chain canonical content, not randomized signature
bytes. Freeze complete wire fields and bounds in reviewed source before use.

File denial alone does not protect a key held in process memory. Require
reviewed collector process/thread DACL and integrity provenance plus native
standard-token controls for read/write memory, handle duplication, injection,
context/impersonation/token and DACL/owner mutation routes. High integrity alone
does not prove no-read-up. New collector threads must be created unimpersonated
under the same reviewed security boundary. Keep the explicit application handle
inheritance list; do not inherit collector/key authority. Missing boundary
facts block dispatch and remain unknown in reports.

## Fixed transport custody

The source-9a47a5d control stopped after bootstrap: the mapped file had an
OS-generated 8.3 alias, which the generic workspace reader deliberately refuses.
Its directory and file ACLs matched the protected-output/inherited-file policy.
The failed run, consumed Start and verified outer cleanup remain preserved.

Signed transport uses a separate closed role enum for bootstrap, ACK, terminal,
result, evidence, completion and signed progress. A caller cannot supply another
path, alias, cap or sharing policy. Each opaque file hold retains its bound
workspace ancestry, exact long-name casing, both directory views, held 128-bit
identity and matching legacy identity, owner/SYSTEM ACL, one link, ordinary disk
type, no reparse point, no EAs and only the unnamed data stream. An observed short
alias is metadata; it is never opened or repaired. General intake, workspace and
disposal readers retain their strict alias policy. No filesystem setting changes.

Completed custody requires exactly these seven files, with no pending or unknown
entries. Closed reads deny write/delete sharing and recheck bytes, identity and
metadata. Only the fixed live progress reader permits append sharing; returned
bytes remain bounded and require complete signed lines and unchanged prior
prefixes. ACK readback uses the same fixed-role boundary after create-only
publication. The mapped handshake copies must match the protected local latch.

After CNG verifies the terminal and all four original raw artifacts, a pure
completion verifier checks their closed receipt policy, hashes and evidence
chain. The semantic reducer consumes those same raw bytes and verified records.
The legacy filesystem completion verifier still refuses undeclared files; it
does not gain a generic allow-extras option. The new raw-data API hashes the
original receipt bytes; the legacy API's canonical receipt digest is unchanged.
Filesystem/crypto fixtures cover complete failed-driver publication and malformed
or missing output. They do not qualify application execution or isolation.

## Crash, retained reads and export

Persist only the public descriptor, request, bootstrap, ACK, latched guest key
and signed evidence. Read/recovery never generate entropy, rekey, re-ACK, resume
the collector, or start the application again. A crash before ACK allows
cleanup only. After ACK publication becomes possible, application execution can
be unknown even if no signed launch record survived. Recovery validates the
approved execution/session bindings before provider query or exact stop.
Valid signed prefixes are partial diagnostics; absent terminal data remains
incomplete. Keep parent cleanup separate from guest-reported cleanup.

The new transaction distinguishes `channel-provider-preflight` from the durable
`provider-start-intent` recorded immediately before invoking provider Start.
Only a complete validated history without pending snapshots and without that
marker proves Start was never authorized. Recovery in that state queries only:
an ID collision or failed query never authorizes stopping that session. Exact
absence permits owned request cleanup. Once the marker exists, asynchronous
Start uncertainty remains; absence alone does not prove Start settled. Historical
transaction schemas do not acquire these semantics.

The trusted local Start record anchors the generated host key. An imported
bundle can fabricate its own host/guest keys and valid signatures. Without
equality to an independently trusted local Start descriptor or a separately
approved issuer anchor, it proves internal integrity only, not authenticated
execution origin. Export must state this distinction. Retained local Read and
export remain provider-zero and must never execute the application.

## Storage and validation gates

Bound complete producer and consumer bytes, record count, per-record overhead,
bootstrap, ACK, terminal and fixed artifact names. Reuse current result,
progress, evidence and receipt caps; account for authentication overhead
explicitly. Monitor output entries/bytes and free volume with bounded no-follow
enumeration while waiting; a breach must stop only the owned Sandbox and retain
a small failure receipt. A writable mapping still permits denial of service:
sampled watchdog limits are **not a filesystem quota** or a guarantee against
disk exhaustion. No host quota/security change is implied by this design.

Before external trials, test wrong keys/bindings/domains, forged early receipts,
replay, reordering, truncation, key replacement, malformed encodings, exact large
integers and all size/count limits. Exercise every durable descriptor/latch/ACK
crash edge and prove cleanup-only recovery without rekey or rerun. Native
first-party controls must prove genuine ordinary/classic outcomes, all local
denial gates, key confidentiality, tampered output rejection, missing output,
transport filling, timeout/overflow, cancellation, interruption and stable
provider-zero retained reads. Independent source review and exact-source
Windows checks precede fresh approved Sandbox qualification. None of these new
channel gates is satisfied by the earlier failed control.

## Primary interface references

- [Windows Sandbox CLI](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-cli)
- [CNG signing](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash)
- [CNG public key export](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey)
- [Process security](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Thread security](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights)
- [Mandatory integrity control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

These references describe OS contracts, not qualification of this proposed
implementation or installed provider wire behavior.
