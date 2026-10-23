// Package library adapts internal validators to the public, read-only library views.
package library

import (
	core "github.com/relux-works/swarma-registrar/internal/enrollment"
)

// Policy holds copied, trusted deployment configuration. Construct it with NewPolicy.
type Policy struct{ inner *core.Policy }

// NewPolicy pins one Ed25519 publisher, a prevalidated canonical audience and
// independently trusted station classifications. It performs no I/O.
func NewPolicy(audience, publisher string, stations map[string]bool) (*Policy, error) {
	p, err := core.NewPolicy(audience, publisher, stations)
	if err != nil {
		return nil, err
	}
	return &Policy{inner: p}, nil
}

// Audience returns the configured canonical server name.
func (p *Policy) Audience() string { return p.inner.Audience() }

// Parse checks schema, ID and publisher signature in normative order.
func (p *Policy) Parse(raw []byte) (*Record, error) {
	var policy *core.Policy
	if p != nil {
		policy = p.inner
	}
	r, err := policy.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &Record{inner: r}, nil
}

// Window describes one current record's exact key encoding and half-open interval.
// Finding a window does not establish current validity or active host state.
type Window struct {
	Key                 string
	NotBefore, NotAfter int64
}

// ValidAt requires both instants to fall in this exact interval, with no skew.
func (w Window) ValidAt(issuedAt, now int64) bool {
	return (core.Window{NotBefore: w.NotBefore, NotAfter: w.NotAfter}).ValidAt(issuedAt, now)
}

// UIDEntry is the verified helper narrowing policy. The caller enforces peer identity.
type UIDEntry = core.UIDEntry

// Record is a read-only verified enrollment, not an admission decision.
// Slice accessors return independent copies; no mutable implementation types escape.
type Record struct{ inner *core.Record }

// ID returns the immutable canonical body ID.
func (r *Record) ID() string { return r.inner.ID }

// Host returns the enrolled host label.
func (r *Record) Host() string { return r.inner.Host }

// Sequence returns the host's sequence position.
func (r *Record) Sequence() int64 { return r.inner.Seq }

// Revoked reports the irreversible host tombstone.
func (r *Record) Revoked() bool { return r.inner.Revoked }

// Keys returns copied key encodings and windows in signed array order.
func (r *Record) Keys() []Window {
	out := make([]Window, len(r.inner.Keys))
	for i, k := range r.inner.Keys {
		out[i] = Window{Key: k.Key.Encoding(), NotBefore: k.NotBefore, NotAfter: k.NotAfter}
	}
	return out
}

// Names returns the exact prefix and a copy of the current explicit claims.
func (r *Record) Names() (string, []string) {
	return r.inner.Prefix, append([]string(nil), r.inner.Explicit...)
}

// UIDMap returns an independent copy, including names and optional executable paths.
func (r *Record) UIDMap() []UIDEntry { return r.inner.Clone().UIDMap }

// CanonicalBody returns an independent copy of the signed CCJ-1 body bytes.
func (r *Record) CanonicalBody() []byte { return append([]byte(nil), r.inner.CanonicalBody...) }

// Permits checks name syntax and ownership only. The caller checks currentness,
// key windows and revocation before using the result as authority.
func (r *Record) Permits(name, audience string) error { return r.inner.Permits(name, audience) }
