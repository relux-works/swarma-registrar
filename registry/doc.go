// Package registry implements specification §§4.3–4.4 snapshot validation and §5 name authorization.
//
// Callers supply complete in-memory entries, protected pin provenance, reconciled
// rollback evidence, signed-commit/ancestry Verifier and durable atomic CAS Store.
// Failed reloads require callers to fence admission.
// The implementation stays internal. Registration-proof verification remains
// internal and is not provided by these public format packages.
//
// This package performs no I/O or network access and has no mutable global or
// process state. Caller-supplied interfaces own external operations; configured
// objects and immutable snapshots hold only their own instance data.
//
// # Loading and snapshot queries
//
// These public aliased methods are listed here for documentation tools that do
// not expand aliases:
//
//	func (l Loader) Load(in Input) (*Snapshot, *HighWater, error)
//	func (s *Snapshot) Revision() string
//	func (s *Snapshot) Current(host string) (*enrollment.Record, bool)
//	func (s *Snapshot) LookupKey(key string) (*enrollment.Record, enrollment.Window, bool)
//	func (s *Snapshot) Authorize(host, name string) error
//	func (h *HighWater) Clone() *HighWater
//
// Load verifies the complete candidate and durably commits high-water state
// before returning authority. Verifier.Verify binds every supplied entry to the
// approved signed commit; Verifier.Descends supplies ancestry. Store.Commit must
// compare prior state and replace it atomically and durably. A failed Load returns
// no snapshot or replacement high-water, and the caller MUST fence admission.
//
// If Store.Commit returns an error, the durable state is indeterminate. Load
// returns no snapshot and no replacement high-water. The caller MUST fence
// admission and MUST NOT continue with either the previous or the new state.
// On the next start, the stored high-water MUST be treated as unreconciled until
// an operator reconciles it. This follows spec §4.4: persistence failure is
// registry_unavailable and fences admission; restored or missing rollback
// evidence fences admission until reconciled.
//
// HighWater.Clone copies retained evidence; it does not reconcile its freshness.
//
// Revision returns the approved full commit ID. Current selects the highest
// validated sequence for an exact host label; returned records are read-only
// views with copying accessors.
//
// LookupKey is exact and current-only: historical-only, unknown, malformed or
// noncanonical key encodings do not match. It deliberately returns revoked or
// out-of-window current records as data. The caller checks the returned key's
// half-open window with Window.ValidAt(iat, now), then host revocation, then name
// authorization. LookupKey does not make those decisions. The caller still owns
// audience validation, clock checks and accounting, plus peer identity where
// required by the helper.
//
// Authorize checks current host presence, revocation, then configured-audience
// name syntax and ownership, in that order. It does not check a key, the clock
// or peer UID. A successful result alone is not an admission decision.
//
// Record.Permits must use the configured Policy.Audience(), never a
// request-selected audience; see the enrollment package documentation.
//
// Stability: any public API or loader behavior change requires its own reviewed
// pull request. Consumers pin a reviewed commit that has landed on main and raise
// that pin in their own reviewed change. api.txt and the API-surface test guard
// exported names, fields and methods only. An unchanged api.txt or green inventory
// test is not approval for a signature or behavior change.
package registry
