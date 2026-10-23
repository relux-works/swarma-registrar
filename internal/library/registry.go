package library

import (
	enrollmentcore "github.com/relux-works/swarma-registrar/internal/enrollment"
	core "github.com/relux-works/swarma-registrar/internal/registry"
)

// Loader validates in-memory snapshots with caller-supplied trust and durability.
// Verifier binds the complete input entries to the approved signed commit, checks
// ancestry, and never follows a branch. Store atomically compares and durably
// replaces high-water state before Load returns authority. See spec §§4.3–4.4.
type Loader struct {
	Policy   *Policy
	Verifier core.Verifier
	Store    core.Store
}

// Load delegates all validation and persistence to the existing phased loader.
// On failure it returns no snapshot or replacement state; callers fence admission.
func (l Loader) Load(in core.Input) (*Snapshot, *core.HighWater, error) {
	var policy *enrollmentcore.Policy
	if l.Policy != nil {
		policy = l.Policy.inner
	}
	s, h, err := (core.Loader{Policy: policy, Verifier: l.Verifier, Store: l.Store}).Load(in)
	if err != nil {
		return nil, nil, err
	}
	out := &Snapshot{inner: s, byKey: make(map[string]string)}
	// Build only from authoritative current records, never historical high-water keys.
	// Core conflict validation guarantees that key ownership is unique across hosts.
	for host := range h.Hosts {
		r, _ := s.Current(host)
		for _, k := range r.Keys {
			out.byKey[k.Key.Encoding()] = host
		}
	}
	return out, h, nil
}

// Snapshot is a read-only view of an atomically persisted, verified snapshot.
// On failed reload, old objects remain recovery evidence and callers MUST fence
// signing/issuance rather than continue using possibly superseded authority.
type Snapshot struct {
	inner *core.Snapshot
	byKey map[string]string
}

// Revision returns the approved full Git object ID.
func (s *Snapshot) Revision() string { return s.inner.Revision() }

// Current returns the highest valid sequence record for an exact host label.
func (s *Snapshot) Current(host string) (*Record, bool) {
	r, ok := s.inner.Current(host)
	if !ok {
		return nil, false
	}
	return &Record{inner: r}, true
}

// LookupKey finds an exact encoded key in current records, including revoked or
// expired records. It neither checks the clock nor authorizes use. Check the
// returned Window.ValidAt and Record.Revoked separately in the required order.
// Historical-only, malformed and unknown encodings do not match.
func (s *Snapshot) LookupKey(key string) (*Record, Window, bool) {
	host, ok := s.byKey[key]
	if !ok {
		return nil, Window{}, false
	}
	r, _ := s.Current(host)
	for _, w := range r.Keys() {
		if w.Key == key {
			return r, w, true
		}
	}
	return nil, Window{}, false
}

// Authorize delegates current host revocation, name syntax and ownership checks.
func (s *Snapshot) Authorize(host, name string) error { return s.inner.Authorize(host, name) }
