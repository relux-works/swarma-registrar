# Matrix audit delivery primitive

`Session` connects authenticated TLS delivery, protected reconciliation and
ordered replay to the adapter's `Audit.Acknowledge` and command issuance.
No live homeserver was used; HR10–HR14 and I16–I21 remain open.

## Caller integration contract

1. Pass only the protected loader's validated origin, full room ID and user;
   arbitrary dot path components and aliases are rejected defensively. Use the
   protected startup loader once; pass its loaded token bytes to `StartSession`.
   There is no token path, reload callback, login or proxy configuration.
   Production uses system TLS roots, TLS >= 1.2,
   no proxy, and refuses every redirect. Each request uses a fresh HTTP/1.1 TLS
   connection via `tls.Dialer`, `Request.Write` and `ReadResponse`; this avoids
   `http.Transport` idle-response logging of peer bytes. Explicit delivery
   attempts are the only retries. `Config.Roots` permits an isolated test trust
   pool; production leaves it nil.
2. Supply `Config.BindingPath` in the same private directory/custody as the local
   audit state. Startup checks the private directory and opened file ownership,
   exact modes 0700/0600, no-follow final open, exclusive lock, file and directory
   fsync. Ancestor directories must remain protected by the operator. A partial
   initial write is retained and fails closed on restart; it is never repaired.
3. Supply the validated chain's nonempty status. A missing binding for a retained
   chain fails. On a fresh empty chain the required `emptyRoom` hook verifies
   empty audit history before the initial empty-room marker is durably stored.
   The caller owns that history scan and subsequent per-filter coverage
   positions; this initial marker alone does not establish current coverage/readiness.
4. Serialize this client, its deliveries and `Close` with delivery reservations.
   Their state mutex must never span network I/O. Make one `Budget` from the
   caller's existing monotonic deadline, at most five
   seconds away. Keep it through queue waiting, checks, delivery, retries, scans,
   coverage persistence and final release. Startup has its own original budget.
5. Pass persisted original CCJ-1 bytes including the LF to `Delivery`. The caller
   remains responsible for full local audit-schema/chain validation; this package checks
   canonical framing and positive safe-integer sequence. It snapshots the bytes,
   derives the LF-inclusive hash and `audit-v0-<hash>` transaction ID, and holds
   fixed endpoint, room, user, device, type and payload across `Attempt` retries.
   A delivery rejects replacement budgets. Retries are explicit, bounded by the
   retained budget; the session schedules prefix recovery without assuming lifetime
   homeserver transaction deduplication.
6. `Attempt` returns `Verified`, a read-back candidate. Only
   `Reconciliation.Complete` can finalize it; the raw hook is package-private.
   Session commits run that wrapper and revalidate local custody before returning
   a hash. Final JWT release checks the same original deadline again. `Position`
   alone never authorizes release.
7. `Session.Begin` owns the pre-candidate reservation through append/Commit.
   Reservation acquisition spends the original request deadline; its state mutex
   is released before network I/O. Start one `Run` worker, cancel/join it before
   `Close`. Recovery opens reconciliation and then runs Recover before delivery,
   never retries a poisoned completion in place, and gives each missing line its
   own budget. Readiness reopens only after coverage and stable local equality.

All exported errors contain static codes only. Network, filesystem, parser and
callback diagnostics are discarded. A parsed whoami user mismatch or
parsed room policy violation yields `audit_room_policy_invalid`;
missing/wrong-type user or device evidence, missing/changed device or binding,
and unavailable startup evidence yield `audit_room_unavailable`.
Readiness failures have type `ReadinessCode` with exported constants for callers.
Delivery failures yield
`audit_unavailable`. Constructor input failures yield `configuration_invalid`.
No package logger is used.

## Policy and head observations

`Start` performs whoami, then one complete room-state read, before creating or
opening a delivery binding. It validates the pinned version-11 nonfederated
create event and creator, absence of predecessor/encryption/tombstone, same-server
joined/invited members, joined audit identity, invite/shared/forbidden access,
and all explicit locked power thresholds and overrides. A malformed state is
unavailable evidence; missing or violated parsed policy is invalid policy.
State/history bodies are streaming-bounded to 4 MiB and 1,024 events; identity,
PUT and read-back bodies retain the 64 KiB cap. Startup keeps the caller's
separate original budget, at most five seconds, through durable binding work.

`CheckPolicy` repeats that state observation. `ReconcileHead` reads backward
`/messages` pages using only the JSON/URL-encoded audit-type filter. Every
returned timeline event must satisfy it, including events after the selected
head. Empty intermediate pages require continuous, nonrepeating tokens. A
missing `end` denotes the served beginning; empty history matches only empty
local history. A nonempty head must match the caller's validated original line
and retained event ID, room, sequence and hash; redacted or conflicting heads
return `audit_room_head_mismatch`. Unavailable or incomplete history returns
`audit_room_unavailable`. No comparison mutates local custody or sends events.
Repeated calls read fresh evidence within the retained budget.

## Durable reconciliation

Under the caller's separate deadline-aware delivery lock, call
`OpenReconciliation` after startup and before the first local append. It opens
an exclusive, no-follow, owner-only append journal at `BindingPath + ".coverage"`.
Checkpoints carry the binding digest, a checksum, prior-checkpoint digest,
newly verified receipts, exact head bytes and one anchor/position per filter.
Receipt deltas preserve prior IDs without rewriting the retained prefix on
every append. New journals are
permitted only during fresh binding creation with empty local and remote audit
history. An existing binding with missing coverage fails even if both heads are
empty. Missing journals on
retained chains, partial records, checksum failures, permission changes and
binding mismatches fail closed; nothing is truncated, reset or repaired.
Checkpoint records are bounded to 16 MiB; exhaustion closes readiness.

`Recover` validates local sequence/hash continuity and walks **every** remote
audit event backward with the audit-only filter. It verifies exact original
bytes, sender, sequence, hash and retained IDs, reconstructs lost receipts and
persists the verified remote prefix before returning. It never sends events.
The caller must still validate the full local audit schema and custody.
`ReconcileHead` remains only a head observation and never proves a prefix.

`Reconciliation.Complete` finalizes the read-back candidate
with predecessor verification, fresh policy observations, both interval scans
and a durable checkpoint. It accepts candidates only from the same client and
uses the original Attempt budget. Call it for every issued, refused and replay
line; it contains no outcome-specific bypass. A fresh audit-only read supplies
the common served-tail upper boundary for both forward scans. Each filter's
saved anchor is re-read with context limit zero and its pagination position
verified before scanning the unchecked interval from the saved served-tail
position. The anchor boundary and coverage boundary are retained separately so
filtered noise cannot cause repeated scans of an already covered interval. Missing coverage never falls
back to a full rescan. Every before/after timeline entry must honor its filter;
anchors and context state receive their own validation. Volatile event age does
not change anchor identity. Policy is re-read after both scans.

Self-sent reader profile updates, joins from approved invitations and leaves
are permitted with previous-membership evidence. Foreign changes, invitations,
bans, kicks and changes by or targeting the audit identity are forbidden except
its own joined profile updates. Incomplete evidence closes readiness. A detected
post-first-event policy/timeline violation records an incident and offending ID
when available; restoration and restart cannot clear a persisted incident.
Non-prefix conflicts are also retained. Scan or checkpoint failure closes
client delivery readiness; `Readiness` retains the diagnostic separately from
the delivery error. A failed/partial write poisons the journal in the
current process; restart validates all retained records before recovery.
Filesystem synchronization cannot be forcibly cancelled: an over-budget sync
may retain evidence, but never acknowledges. Keep the original Budget through
all subsequent caller checks.

The production session initializes/reopens reconciliation and Recover in order,
checks before each candidate, and runs Complete for issued, refused and replay
lines. Its single worker retries at 1/2/4/8/16/30 seconds and sends no verified
prefix line again, including after a lost receipt. Recovery never returns JWTs
or restores nonces. Incident replacement is operator-only under spec §9.1.4;
old bindings and evidence are never silently replaced. Gate (c) awaits independent
integration review and validation. Live HR10–HR14 and I16–I21 remain open;
TLS fake tests cannot qualify homeserver deduplication loss, durability or retention.

## Tools and evidence

| Tool | Purpose and command | Output |
| --- | --- | --- |
| Go 1.26.10 | `GOTOOLCHAIN=local go test -count=1 ./internal/adapters/matrixaudit` | Native portable fake-TLS-server tests; no external services |
| Go vet | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go vet ./internal/adapters/matrixaudit` | Static diagnostics only |
| Go test compiler | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go test -c ./internal/adapters/matrixaudit -o /tmp/matrixaudit.test` | Linux test binary, not executed on macOS |
| Python 3 | `python3 .scripts/check-hygiene.py --base 32e8675cfddffd30f440653b5428e98a84261158` | Public hygiene diagnostics |

Command integration checks: `go test ./cmd/registrar -run TestMatrixCommand -count=1`.
They use the policy-enforcing TLS fake with isolated trust and assert exactly
one JWT for acknowledged issuance, zero for acknowledgement failures, consumed
nonces, durable refusals and automatic prefix-only recovery. Linux terminal
qualification remains Linux-only; the non-Linux terminal implementation refuses.
