# Matrix audit delivery primitive

This package is deliberately separate from `Audit.Acknowledge`, issuance,
readiness and replay. It supplies HTTPS transport, an exclusive durable delivery
binding, immutable per-line PUT attempts, and exact read-back verification.
No live homeserver was used for package validation.

## Caller integration contract

1. Use the protected startup loader once; pass its loaded token bytes to `Start`.
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
callback diagnostics are discarded. A parsed whoami user mismatch yields
`audit_room_policy_invalid`; missing/changed device or binding and unavailable
startup evidence yield `audit_room_unavailable`. Delivery failures yield
`audit_unavailable`. Constructor input failures yield `configuration_invalid`.
No package logger is used.

## Tools and evidence

| Tool | Purpose and command | Output |
| --- | --- | --- |
| Go 1.26.10 | `GOTOOLCHAIN=local go test -count=1 ./internal/adapters/matrixaudit` | Native portable fake-TLS-server tests; no external services |
| Go vet | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go vet ./internal/adapters/matrixaudit` | Static diagnostics only |
| Go test compiler | `GOTOOLCHAIN=local GOOS=linux GOARCH=arm64 go test -c ./internal/adapters/matrixaudit -o /tmp/matrixaudit.test` | Linux test binary, not executed on macOS |
| Python 3 | `python3 .scripts/check-hygiene.py --base cae5ab34ffe7cc99edb8b385d6a43c575513aa7e` | Public hygiene diagnostics |
