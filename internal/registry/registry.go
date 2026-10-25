// Package registry validates complete in-memory snapshots before atomic publication.
package registry

import (
	"regexp"
	"sort"
	"strings"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/internal/revision"
)

const MaxEntries = 10000
const MaxBytes = 16 * 1024 * 1024

type EntryKind uint8

const (
	Regular EntryKind = iota
	Symlink
	Other
)

type Entry struct {
	Path  string
	Bytes []byte
	Kind  EntryKind
}

// Verifier stands in for §4.3: "The pinned commit MUST have a valid signature"
// under configured pins and "MUST be the reviewed protected-branch revision
// approved by the operator." Verify must also bind this COMPLETE enrollment
// entry set (including entry types and bytes) to that exact approved commit,
// from a protected configured source. It must not fetch or follow a branch.
// Descends stands in for §4.4: "A replacement pin MUST be the same revision or
// a Git descendant." False means rollback; unavailable evidence fails closed.
type Verifier interface {
	Verify(revision string, entries []Entry) error
	Descends(candidate, previous string) (bool, error)
}

// Store stands in for §4.4: "The new high-water state MUST be persisted
// atomically before new authority is usable." Commit must compare previous
// against durable current state, atomically replace it, and report success only
// after durability.
//
// If Store.Commit returns an error, the durable state is indeterminate. Load
// returns no snapshot and no replacement high-water. The caller MUST fence
// admission and MUST NOT continue with either the previous or the new state.
// On the next start, the stored high-water MUST be treated as unreconciled until
// an operator reconciles it. This follows spec §4.4: persistence failure is
// registry_unavailable and fences admission; restored or missing rollback
// evidence fences admission until reconciled.
//
// This interface supplies no file implementation or cross-process locking.
type Store interface {
	Commit(previous *HighWater, next HighWater) error
}

type HostWater struct {
	Seq     int64
	ID      string
	Revoked bool
	History map[int64]string
}

// HighWater retains immutable historical body IDs and ownership attribution,
// including removed keys/names, so a missing history file cannot release a claim
// or turn a cross-host conflict into a lower-priority omission diagnostic.
type HighWater struct {
	Revision              string
	Hosts                 map[string]HostWater
	KeyOwners, NameOwners map[string]string
}

func (h *HighWater) Clone() *HighWater {
	if h == nil {
		return nil
	}
	out := &HighWater{Revision: h.Revision, Hosts: make(map[string]HostWater, len(h.Hosts)), KeyOwners: cloneMap(h.KeyOwners), NameOwners: cloneMap(h.NameOwners)}
	if h.Hosts == nil {
		out.Hosts = nil
	}
	for host, water := range h.Hosts {
		copy := water
		copy.History = make(map[int64]string, len(water.History))
		if water.History == nil {
			copy.History = nil
		}
		for seq, id := range water.History {
			copy.History[seq] = id
		}
		out.Hosts[host] = copy
	}
	return out
}
func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Input contains a complete candidate entry list. FirstUse is an explicit
// operator bootstrap decision, never inferred from missing state. Reconciled
// attests externally verified freshness of nonbootstrap rollback evidence; a
// restored/lost local file alone cannot establish this (§4.4 restore fence).
type Input struct {
	Revision             string
	Entries              []Entry
	Retained             *HighWater
	FirstUse, Reconciled bool
}
type Loader struct {
	// ObjectFormat is the protected repository profile: exactly "sha1" or "sha256".
	ObjectFormat string
	Policy       *enrollment.Policy
	Verifier     Verifier
	Store        Store
}

// Diagnostic keeps the stable refusal separate from restricted Git-path context.
// Error emits only the code; Path never becomes an HTTP error detail.
type Diagnostic struct {
	Code refusal.Code
	Path string
}

func (d *Diagnostic) Error() string                   { return string(d.Code) }
func (d *Diagnostic) Unwrap() error                   { return refusal.New(d.Code) }
func diagnostic(code refusal.Code, path string) error { return &Diagnostic{Code: code, Path: path} }
func documentError(err error, path string) error {
	for _, code := range []refusal.Code{refusal.EnrollmentMalformed, refusal.EnrollmentSigsUnsupported, refusal.EnrollmentIDMismatch, refusal.EnrollmentSignatureInvalid, refusal.RegistryUnavailable} {
		if refusal.Is(err, code) {
			return diagnostic(code, path)
		}
	}
	return diagnostic(refusal.RegistryUnavailable, path)
}

// Snapshot owns private records; accessors return copies. A Snapshot is only
// returned after all phases and the caller-supplied atomic Store succeed.
// On a failed reload the caller MUST fence admission; unchanged old objects are
// recovery evidence, never permission to keep serving a superseded snapshot.
type Snapshot struct {
	revision, audience string
	current            map[string]*enrollment.Record
}

func (s *Snapshot) Revision() string { return s.revision }
func (s *Snapshot) Current(host string) (*enrollment.Record, bool) {
	r, ok := s.current[host]
	return r.Clone(), ok
}
func (s *Snapshot) Authorize(host, name string) error {
	r, ok := s.current[host]
	if !ok {
		return refusal.New(refusal.NameNotPermitted)
	}
	if r.Revoked {
		return refusal.New(refusal.HostRevoked)
	}
	return r.Permits(name, s.audience)
}

// Load completes each phase over every ordered file before the next phase.
// Every failure returns nil authority and nil replacement state. It never edits
// the supplied entries, retained state or previously returned snapshots.
func (l Loader) Load(in Input) (*Snapshot, *HighWater, error) {
	fail := func(err error) (*Snapshot, *HighWater, error) { return nil, nil, err }
	if l.Policy == nil || l.Verifier == nil || l.Store == nil || !revision.Valid(l.ObjectFormat, in.Revision) {
		return fail(diagnostic(refusal.RegistryUnavailable, ""))
	}
	if in.FirstUse {
		if in.Retained != nil {
			return fail(diagnostic(refusal.RegistryUnavailable, ""))
		}
	} else if in.Retained == nil || !in.Reconciled || !validRetained(in.Retained, l.ObjectFormat) {
		return fail(diagnostic(refusal.RegistryUnavailable, ""))
	}
	previous := in.Retained.Clone()
	entries, err := prepareEntries(in.Entries)
	if err != nil {
		return fail(err)
	}
	if err = l.Verifier.Verify(in.Revision, cloneEntries(entries)); err != nil {
		return fail(diagnostic(refusal.RegistryUnavailable, ""))
	}
	docs := make([]*enrollment.Document, len(entries))
	// Phase 1: all files must pass envelope/CCJ/size checks before reserved members.
	for i, e := range entries {
		docs[i], err = l.Policy.Decode(e.Bytes)
		if err != nil {
			return fail(documentError(err, e.Path))
		}
	}
	// Phase 2: reserved future authority outranks any body schema/id/signature defect.
	for i, d := range docs {
		if err = d.CheckReserved(); err != nil {
			return fail(documentError(err, entries[i].Path))
		}
	}
	// Phase 3: all record schemas, keys, names, UID maps and host classifications.
	for i, d := range docs {
		if err = d.CheckBody(); err != nil {
			return fail(documentError(err, entries[i].Path))
		}
	}
	// Phase 4: all body IDs, before any publisher equation.
	for i, d := range docs {
		if err = d.CheckID(); err != nil {
			return fail(documentError(err, entries[i].Path))
		}
	}
	// Phase 5: only the one policy-pinned publisher can authenticate each record.
	records := make([]*enrollment.Record, len(docs))
	for i, d := range docs {
		records[i], err = d.Verify()
		if err != nil {
			return fail(documentError(err, entries[i].Path))
		}
	}
	// Phase 6: global and historical ownership conflicts, before rollback.
	if index := conflict(records, previous); index >= 0 {
		return fail(diagnostic(refusal.RegistryConflict, entries[index].Path))
	}
	// Phase 7: revision and historical/tombstone monotonicity.
	if previous != nil && in.Revision != previous.Revision {
		descends, err := l.Verifier.Descends(in.Revision, previous.Revision)
		if err != nil {
			return fail(diagnostic(refusal.RegistryUnavailable, ""))
		}
		if !descends {
			return fail(diagnostic(refusal.RegistryRollback, ""))
		}
	}
	if path, failed := rollback(records, entries, previous, in.FirstUse); failed {
		return fail(diagnostic(refusal.RegistryRollback, path))
	}
	snapshot, next := build(in.Revision, l.Policy.Audience(), records)
	if err = l.Store.Commit(previous.Clone(), *next.Clone()); err != nil {
		return fail(diagnostic(refusal.RegistryUnavailable, ""))
	}
	return snapshot, next.Clone(), nil
}

func enrolledPath(path string) bool {
	return strings.HasPrefix(path, "enrollments/") && strings.HasSuffix(path, ".json") && !strings.Contains(path[len("enrollments/"):], "/")
}
func prepareEntries(input []Entry) ([]Entry, error) {
	total := 0
	selected := make([]Entry, 0)
	paths := map[string]bool{}
	for _, e := range input {
		if !enrolledPath(e.Path) {
			continue
		}
		if len(selected) >= MaxEntries || e.Kind != Regular || paths[e.Path] || len(e.Bytes) > MaxBytes-total {
			return nil, diagnostic(refusal.RegistryUnavailable, "")
		}
		paths[e.Path] = true
		total += len(e.Bytes)
		selected = append(selected, e)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path }) // Go strings compare unsigned bytes.
	return cloneEntries(selected), nil
}
func cloneEntries(in []Entry) []Entry {
	out := make([]Entry, len(in))
	for i, e := range in {
		out[i] = e
		out[i].Bytes = append([]byte(nil), e.Bytes...)
	}
	return out
}

var idPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validRetained(h *HighWater, objectFormat string) bool {
	if !revision.Valid(objectFormat, h.Revision) || h.Hosts == nil || h.KeyOwners == nil || h.NameOwners == nil {
		return false
	}
	for host, w := range h.Hosts {
		if !enrollment.ValidHost(host) || w.Seq < 1 || w.Seq > ccj.MaxInteger || !idPattern.MatchString(w.ID) || len(w.History) == 0 || w.History[w.Seq] != w.ID {
			return false
		}
		for seq, id := range w.History {
			if seq < 1 || seq > w.Seq || !idPattern.MatchString(id) {
				return false
			}
		}
	}
	for _, host := range h.KeyOwners {
		if _, ok := h.Hosts[host]; !ok {
			return false
		}
	}
	for _, host := range h.NameOwners {
		if _, ok := h.Hosts[host]; !ok {
			return false
		}
	}
	return true
}

func conflict(records []*enrollment.Record, previous *HighWater) int {
	bad := make([]bool, len(records))
	positions := map[string]map[int64][]int{}
	keyClaims := map[string][]int{}
	nameClaims := map[string][]int{}
	for i, r := range records {
		if positions[r.Host] == nil {
			positions[r.Host] = map[int64][]int{}
		}
		positions[r.Host][r.Seq] = append(positions[r.Host][r.Seq], i)
		for _, k := range r.Keys {
			key := k.Key.Encoding()
			keyClaims[key] = append(keyClaims[key], i)
			if previous != nil {
				if host, known := previous.KeyOwners[key]; known && host != r.Host {
					bad[i] = true
				}
			}
		}
		for _, name := range r.Explicit {
			nameClaims[name] = append(nameClaims[name], i)
			if host, structured := registration.StructuredHost(name); structured && host != r.Host {
				bad[i] = true
			}
			if previous != nil {
				if host, known := previous.NameOwners[name]; known && host != r.Host {
					bad[i] = true
				}
			}
		}
	}
	for _, seqs := range positions {
		for _, indices := range seqs {
			if len(indices) > 1 {
				for _, i := range indices {
					bad[i] = true
				}
			}
		}
	}
	for _, claims := range []map[string][]int{keyClaims, nameClaims} {
		for _, indices := range claims {
			host := records[indices[0]].Host
			multiple := false
			for _, i := range indices {
				if records[i].Host != host {
					multiple = true
					break
				}
			}
			if multiple {
				for _, i := range indices {
					bad[i] = true
				}
			}
		}
	}
	for i, failed := range bad {
		if failed {
			return i
		}
	}
	return -1
}
func rollback(records []*enrollment.Record, entries []Entry, previous *HighWater, firstUse bool) (string, bool) {
	if len(records) == 0 && !firstUse {
		return "", true
	}
	positions := map[string]map[int64]string{}
	revokedAt := map[string]int64{}
	for _, r := range records {
		if positions[r.Host] == nil {
			positions[r.Host] = map[int64]string{}
		}
		positions[r.Host][r.Seq] = r.ID
		if r.Revoked {
			if seq, seen := revokedAt[r.Host]; !seen || r.Seq < seq {
				revokedAt[r.Host] = r.Seq
			}
		}
	}
	for i, r := range records {
		if seq, revoked := revokedAt[r.Host]; revoked && !r.Revoked && r.Seq > seq {
			return entries[i].Path, true
		}
		if previous != nil {
			old, known := previous.Hosts[r.Host]
			if known {
				if id, seen := old.History[r.Seq]; seen && id != r.ID {
					return entries[i].Path, true
				}
				if old.Revoked && !r.Revoked && r.Seq > old.Seq {
					return entries[i].Path, true
				}
			}
		}
	}
	if previous != nil {
		for host, water := range previous.Hosts {
			for seq, id := range water.History {
				if positions[host][seq] != id {
					return "", true
				}
			}
		}
	}
	return "", false
}
func build(revision, audience string, records []*enrollment.Record) (*Snapshot, *HighWater) {
	snapshot := &Snapshot{revision: revision, audience: audience, current: map[string]*enrollment.Record{}}
	next := &HighWater{Revision: revision, Hosts: map[string]HostWater{}, KeyOwners: map[string]string{}, NameOwners: map[string]string{}}
	for _, r := range records {
		water, seen := next.Hosts[r.Host]
		if !seen {
			water.History = map[int64]string{}
		}
		water.History[r.Seq] = r.ID
		if r.Seq > water.Seq {
			water.Seq, water.ID, water.Revoked = r.Seq, r.ID, r.Revoked
			snapshot.current[r.Host] = r.Clone()
		}
		next.Hosts[r.Host] = water
		for _, k := range r.Keys {
			next.KeyOwners[k.Key.Encoding()] = r.Host
		}
		for _, name := range r.Explicit {
			next.NameOwners[name] = r.Host
		}
	}
	return snapshot, next
}
