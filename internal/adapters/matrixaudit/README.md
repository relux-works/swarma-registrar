# Matrix audit delivery primitive

This package is deliberately separate from `Audit.Acknowledge`, issuance,
complete readiness and replay. It supplies HTTPS transport, an exclusive durable
delivery binding, immutable per-line PUT attempts, exact read-back verification,
startup identity/current-state policy validation and filtered head comparison.
No live homeserver was used for package validation.

## Caller integration contract

1. Pass only the protected loader's validated origin, full room ID and user;
   arbitrary dot path components and aliases are rejected defensively. Use the
   protected startup loader once; pass its loaded token bytes to `Start`.
   There is no token path, reload callback, login, CA configuration or proxy
   configuration in this package. Production uses system TLS roots, TLS >= 1.2,
   no proxy, and refuses every redirect. Each request uses a fresh HTTP/1.1 TLS
   connection via `tls.Dialer`, `Request.Write` and `ReadResponse`; this avoids
   `http.Transport` idle-response logging of peer bytes. Explicit delivery
   attempts are the only retries. The test trust-pool constructor exists
   only in `_test.go`.
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
4. Serialize this client, its deliveries and `Close` under the caller's delivery
   lock. Make one `Budget` from the caller's existing monotonic deadline, at most five
   seconds away. Keep it through queue waiting, checks, delivery, retries, scans,
   coverage persistence and final release. Startup has its own original budget.
5. Pass persisted original CCJ-1 bytes including the LF to `Delivery`. The caller
   remains responsible for full local audit-schema/chain validation; this package checks
   canonical framing and positive safe-integer sequence. It snapshots the bytes,
   derives the LF-inclusive hash and `audit-v0-<hash>` transaction ID, and holds
   fixed endpoint, room, user, device, type and payload across `Attempt` retries.
   A delivery rejects replacement budgets. Retries are explicit, bounded by the
   retained budget; this package does not schedule recovery or assume lifetime
   homeserver transaction deduplication.
6. `Attempt` returns `Verified`, a candidate read-back position. Call `Complete`
   with a required hook performing predecessor/policy checks, both incremental
   coverage scans, durable coverage write and final checks inside the same
   deadline-bearing context and budget. Only successful hook completion strictly
   before the original deadline succeeds. Final JWT release must also check that
   original budget. `Position` is a served event ID/room/sequence/hash, not a
   pagination token or independent proof of homeserver durability.

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

The caller must own a separate deadline-aware delivery lock and invoke these
observations at the required points. They do not implement chain-wide prefix
verification, lost-receipt recovery, predecessor checks, membership transition
scans, durable coverage or the persistent timeline fence. Policy restoration or
head equality is never authority to clear such a fence. The initial empty-room
hook still belongs to the caller. Replay, the operator incident-replacement
path and `adapters.Remote`/command wiring are pending. No release path was added;
code-level gate (c), live HR10–HR14 and I16–I21 remain open. Only successful
`Verified.Complete` after the required coverage hook can gate future JWT release.

The policy-enforcing local TLS fake rejects reader writes and all redactions,
with an audit-user append as its control. Policy/head/identity negatives have
adjacent valid controls; time and response limits are tested without live access.
These package tests establish neither command release behavior nor live policy,
durability, deduplication, retention or deployment qualification.

## Tools and evidence

| Tool | Purpose and command | Output |
| --- | --- | --- |
| Go 1.26.10 | `GOTOOLCHAIN=local go test -count=1 ./internal/adapters/matrixaudit` | Native portable fake-TLS-server tests; no external services |
| Go vet | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go vet ./internal/adapters/matrixaudit` | Static diagnostics only |
| Go test compiler | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go test -c ./internal/adapters/matrixaudit -o /tmp/matrixaudit.test` | Linux test binary, not executed on macOS |
| Python 3 | `python3 .scripts/check-hygiene.py --base 8402c19c53828c4f81d89677ed4af4613c0e63f3` | Public hygiene diagnostics |
