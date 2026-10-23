// Package enrollment implements specification §§4.1–4.3 enrollment schema and publisher verification, and §5 names.
//
// Callers supply one pinned Ed25519 publisher, a validated canonical audience and
// independently trusted host classifications. Peer identity enforcement belongs
// to the helper.
// The implementation stays internal. Registration-proof verification remains
// internal and is not provided by these public format packages.
//
// This package performs no I/O or network access and has no mutable global or
// process state. Caller-supplied interfaces own external operations; configured
// objects and immutable snapshots hold only their own instance data.
//
// # Policy and verified records
//
// These public aliased methods are listed here for documentation tools that do
// not expand aliases:
//
//	func (p *Policy) Audience() string
//	func (p *Policy) Parse(raw []byte) (*Record, error)
//	func (r *Record) ID() string
//	func (r *Record) Host() string
//	func (r *Record) Sequence() int64
//	func (r *Record) Revoked() bool
//	func (r *Record) Keys() []Window
//	func (r *Record) Names() (string, []string)
//	func (r *Record) UIDMap() []UIDEntry
//	func (r *Record) CanonicalBody() []byte
//	func (r *Record) Permits(name, audience string) error
//	func (w Window) ValidAt(issuedAt, now int64) bool
//
// Policy.Parse verifies schema, body ID and the single pinned publisher's
// signature in order; it does not select current registry authority. Record
// accessors expose the verified ID, host, sequence and tombstone. Keys preserves
// signed array order with encoded key strings; Names returns the exact prefix
// and explicit claims. Keys, Names, UIDMap (including executable path pointers)
// and CanonicalBody return independent copies.
//
// Record.Permits checks name syntax and ownership only. Always call it with the
// configured Policy.Audience(), never a request-selected audience. The caller
// must establish currentness, key-window validity and host revocation first.
// Window.ValidAt(iat, now) requires both instants in the same exact half-open
// interval [NotBefore, NotAfter), without skew. Registry LookupKey deliberately
// returns revoked or out-of-window current records as data: check the returned
// window, then host revocation, then name authorization. The caller still owns
// audience validation, clock checks, accounting and helper peer-UID enforcement.
//
// Stability: any public API or loader behavior change requires its own reviewed
// pull request. Consumers pin a reviewed commit that has landed on main and raise
// that pin in their own reviewed change. api.txt and the API-surface test guard
// exported names, fields and methods only. An unchanged api.txt or green inventory
// test is not approval for a signature or behavior change.
package enrollment
