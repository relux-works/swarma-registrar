package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

const revA = "1111111111111111111111111111111111111111"
const revB = "2222222222222222222222222222222222222222"

func testPrivate(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}
func testPublic(b byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(testPrivate(b).Public().(ed25519.PublicKey))
}
func record(host string, seq int64, key byte, state string, explicit ...string) map[string]any {
	names := make([]any, len(explicit))
	for i, n := range explicit {
		names[i] = n
	}
	return map[string]any{"type": "enrollment/1", "host": host, "seq": seq, "state": state, "keys": []any{map[string]any{"key": testPublic(key), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": host + "_", "explicit": names}}
}
func entry(t *testing.T, path string, b map[string]any, signer byte) Entry {
	t.Helper()
	pre, id, err := envelope.SigningInput(envelope.Enrollment, b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": b, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(testPrivate(signer), pre))}, refusal.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return Entry{Path: path, Bytes: raw, Kind: Regular}
}

type verifier struct {
	fail, ancestryError bool
	descendant          bool
	seen                []string
	ancestryCalls       int
}

func (v *verifier) Verify(revision string, entries []Entry) error {
	for _, e := range entries {
		v.seen = append(v.seen, e.Path)
	}
	if v.fail {
		return errors.New("unapproved revision")
	}
	return nil
}
func (v *verifier) Descends(candidate, previous string) (bool, error) {
	v.ancestryCalls++
	if v.ancestryError {
		return false, errors.New("ancestry unavailable")
	}
	return v.descendant, nil
}

type store struct {
	fail  bool
	calls int
	state *HighWater
}

func (s *store) Commit(previous *HighWater, next HighWater) error {
	s.calls++
	if s.fail {
		return errors.New("persistence unavailable")
	}
	if !reflect.DeepEqual(s.state, previous) {
		return errors.New("stale previous state")
	}
	s.state = next.Clone()
	return nil
}
func loader(t *testing.T) (Loader, *verifier, *store) {
	t.Helper()
	p, err := enrollment.NewPolicy("example.org", testPublic(1), map[string]bool{"host-a": false, "host-b": false, "-node": false})
	if err != nil {
		t.Fatal(err)
	}
	v := &verifier{descendant: true}
	s := &store{}
	return Loader{Policy: p, Verifier: v, Store: s}, v, s
}
func bootstrap(t *testing.T, l Loader, entries ...Entry) (*Snapshot, *HighWater) {
	t.Helper()
	s, h, err := l.Load(Input{Revision: revA, Entries: entries, FirstUse: true})
	if err != nil {
		t.Fatal(err)
	}
	return s, h
}
func verdict(t *testing.T, l Loader, in Input, code refusal.Code, path string) {
	t.Helper()
	before := in.Retained.Clone()
	snapshot, next, err := l.Load(in)
	if !refusal.Is(err, code) || snapshot != nil || next != nil {
		t.Fatalf("got snapshot=%v next=%v err=%v", snapshot, next, err)
	}
	var diagnostic *Diagnostic
	if !errors.As(err, &diagnostic) || diagnostic.Path != path {
		t.Fatalf("path got %v, expected %q", diagnostic, path)
	}
	if !reflect.DeepEqual(before, in.Retained) {
		t.Fatal("retained state mutated")
	}
}

// Snapshot-wide phases dominate path order; within a phase the first failing Git path supplies context.
func TestSnapshotPhaseOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		l, _, s := loader(t)
		a, b := "enrollments/a.json", "enrollments/z.json"
		if reverse {
			a, b = b, a
		}
		badSignature := entry(t, a, record("host-a", 1, 2, "active"), 3)
		reserved := record("host-b", 1, 4, "active")
		reserved["sigs"] = nil
		verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{badSignature, entry(t, b, reserved, 1)}}, refusal.EnrollmentSigsUnsupported, b)
		if s.calls != 0 {
			t.Fatal("partial persistence")
		}
		reserved["sigs"] = []any{}
		reserved["type"] = false
		verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{entry(t, b, reserved, 1), badSignature}}, refusal.EnrollmentSigsUnsupported, b)
		good := []Entry{entry(t, b, record("host-b", 1, 4, "active"), 1), entry(t, a, record("host-a", 1, 2, "active"), 1)}
		bootstrap(t, l, good...)
	}
	l, _, s := loader(t)
	badA := entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 3)
	badZ := entry(t, "enrollments/z.json", record("host-b", 1, 4, "active"), 3)
	verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{badZ, badA}}, refusal.EnrollmentSignatureInvalid, badA.Path)
	if s.calls != 0 {
		t.Fatal("saved invalid snapshot")
	}
	l, _, _ = loader(t)
	bad := record("host-a", 2, 2, "active")
	bad["seq"] = "2"
	older := entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)
	verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{older, entry(t, "enrollments/z.json", bad, 1)}}, refusal.EnrollmentMalformed, "enrollments/z.json")
	bootstrap(t, l, older)
}

// Conflicts are checked over all retained candidate history before rollback; removal never releases ownership across hosts.
func TestHistoryConflictsAndTombstones(t *testing.T) {
	cases := []struct {
		name    string
		records []map[string]any
		code    refusal.Code
	}{
		{"duplicate position", []map[string]any{record("host-a", 1, 2, "active"), record("host-a", 1, 2, "active")}, refusal.RegistryConflict},
		{"cross host key", []map[string]any{record("host-a", 1, 2, "active"), record("host-b", 1, 2, "active")}, refusal.RegistryConflict},
		{"key after revoked", []map[string]any{record("host-a", 1, 2, "revoked"), record("host-b", 1, 2, "active")}, refusal.RegistryConflict},
		{"legacy claimed elsewhere after removal", []map[string]any{record("host-a", 1, 2, "active", "legacy.dev"), record("host-a", 2, 2, "active"), record("host-b", 1, 4, "active", "legacy.dev")}, refusal.RegistryConflict},
		{"borrow structured", []map[string]any{record("host-a", 1, 2, "active", "host-b_project_role")}, refusal.RegistryConflict},
		{"active after revoked", []map[string]any{record("host-a", 1, 2, "revoked"), record("host-a", 2, 2, "active")}, refusal.RegistryRollback},
		{"conflict before rollback", []map[string]any{record("host-a", 1, 2, "revoked"), record("host-a", 2, 2, "active"), record("host-b", 1, 2, "active")}, refusal.RegistryConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _, s := loader(t)
			entries := make([]Entry, len(tc.records))
			for i, b := range tc.records {
				entries[i] = entry(t, fmt.Sprintf("enrollments/%02d.json", i), b, 1)
			}
			path := entries[0].Path
			if tc.code == refusal.RegistryRollback {
				path = entries[1].Path
			}
			verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: entries}, tc.code, path)
			if s.calls != 0 {
				t.Fatal("persisted conflict")
			}
			bootstrap(t, l, entry(t, "enrollments/good.json", record("host-a", 1, 2, "active"), 1))
		})
	}
	l, _, _ := loader(t)
	snapshot, high := bootstrap(t, l, entry(t, "enrollments/z.json", record("host-a", 1, 2, "active", "legacy.dev"), 1), entry(t, "enrollments/a.json", record("host-a", 2, 2, "active"), 1), entry(t, "enrollments/m.json", record("host-a", 3, 2, "active", "legacy.dev"), 1))
	current, ok := snapshot.Current("host-a")
	if !ok || current.Seq != 3 || high.Hosts["host-a"].Seq != 3 {
		t.Fatal("not highest seq")
	}
	if err := snapshot.Authorize("host-a", "legacy.dev"); err != nil {
		t.Fatal(err)
	}
}

// Lost/replaced history, non-descendant pins and tombstone resurrection refuse atomically without changing earlier authority/state.
func TestRollbackAndAtomicity(t *testing.T) {
	cases := []struct {
		name     string
		edit     func([]Entry) []Entry
		ancestry bool
	}{
		{"lower seq", func(e []Entry) []Entry { return []Entry{e[0], e[2]} }, true},
		{"equal seq changed id", func(e []Entry) []Entry {
			e[1] = entry(t, e[1].Path, record("host-a", 2, 2, "active", "new.dev"), 1)
			return e
		}, true},
		{"drop host", func(e []Entry) []Entry { return e[:2] }, true},
		{"rewrite history", func(e []Entry) []Entry {
			e[0] = entry(t, e[0].Path, record("host-a", 1, 2, "active", "new.dev"), 1)
			return e
		}, true},
		{"revision ancestor", func(e []Entry) []Entry { return e }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, v, s := loader(t)
			entries := []Entry{entry(t, "enrollments/a.json", record("host-a", 1, 2, "active", "legacy.dev"), 1), entry(t, "enrollments/b.json", record("host-a", 2, 2, "active", "legacy.dev"), 1), entry(t, "enrollments/c.json", record("host-b", 1, 4, "active"), 1)}
			previous, retained := bootstrap(t, l, entries...)
			before := retained.Clone()
			v.descendant = tc.ancestry
			candidate, next, err := l.Load(Input{Revision: revB, Entries: tc.edit(append([]Entry(nil), entries...)), Retained: retained, Reconciled: true})
			if !refusal.Is(err, refusal.RegistryRollback) || candidate != nil || next != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, retained) || !reflect.DeepEqual(before, s.state) || s.calls != 1 {
				t.Fatal("failure changed state")
			}
			if err := previous.Authorize("host-a", "legacy.dev"); err != nil {
				t.Fatal(err)
			}
			v.descendant = true
			candidate, next, err = l.Load(Input{Revision: revB, Entries: entries, Retained: retained, Reconciled: true})
			if err != nil || candidate == nil || next.Revision != revB {
				t.Fatal(err)
			}
		})
	}
}

// Trust/type/aggregate/freshness prerequisites fail before document parsing; empty snapshots require explicit first bootstrap.
func TestRegistryPrerequisites(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Input, *verifier, *store)
		code  refusal.Code
	}{
		{"bad revision", func(in *Input, v *verifier, s *store) { in.Revision = "main" }, refusal.RegistryUnavailable},
		{"unverified commit", func(in *Input, v *verifier, s *store) { v.fail = true }, refusal.RegistryUnavailable},
		{"symlink", func(in *Input, v *verifier, s *store) { in.Entries[0].Kind = Symlink }, refusal.RegistryUnavailable},
		{"nonregular", func(in *Input, v *verifier, s *store) { in.Entries[0].Kind = Other }, refusal.RegistryUnavailable},
		{"too many entries", func(in *Input, v *verifier, s *store) {
			in.Entries = make([]Entry, 10001)
			for i := range in.Entries {
				in.Entries[i].Path = fmt.Sprintf("enrollments/%05d.json", i)
			}
		}, refusal.RegistryUnavailable},
		{"too many bytes", func(in *Input, v *verifier, s *store) { in.Entries[0].Bytes = make([]byte, 16*1024*1024+1) }, refusal.RegistryUnavailable},
		{"lost state", func(in *Input, v *verifier, s *store) { in.FirstUse = false }, refusal.RegistryUnavailable},
		{"persistence", func(in *Input, v *verifier, s *store) { s.fail = true }, refusal.RegistryUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, v, s := loader(t)
			in := Input{Revision: revA, FirstUse: true, Entries: []Entry{entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)}}
			tc.setup(&in, v, s)
			snapshot, next, err := l.Load(in)
			if !refusal.Is(err, tc.code) || snapshot != nil || next != nil || s.state != nil {
				t.Fatalf("got %v", err)
			}
			l, _, _ = loader(t)
			bootstrap(t, l, entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1))
		})
	}
	l, _, s := loader(t)
	_, retained := bootstrap(t, l)
	verdict(t, l, Input{Revision: revA, Retained: retained, Reconciled: true}, refusal.RegistryRollback, "")
	if s.calls != 1 {
		t.Fatal("empty reinstalled")
	}
}

// Published snapshots/high-water own their data, removed names lose permission, and callers cannot mutate installed authority through accessors.
func TestSnapshotAuthorizationAndCopies(t *testing.T) {
	l, _, s := loader(t)
	old := entry(t, "enrollments/z.json", record("host-a", 1, 2, "active", "legacy.dev"), 1)
	current := entry(t, "enrollments/a.json", record("host-a", 2, 2, "active"), 1)
	snapshot, high := bootstrap(t, l, current, old)
	for _, name := range []string{"host-a_project_role", "host-a_project_role-q"} {
		if err := snapshot.Authorize("host-a", name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"legacy.dev", "host-a_project_role_extra", "host-b_project_role"} {
		if !refusal.Is(snapshot.Authorize("host-a", name), refusal.NameNotPermitted) {
			t.Fatal(name)
		}
	}
	if !refusal.Is(snapshot.Authorize("host-a", "Upper"), refusal.NameInvalid) {
		t.Fatal("syntax")
	}
	copy, _ := snapshot.Current("host-a")
	copy.Explicit = append(copy.Explicit, "legacy.dev")
	copy.Keys = nil
	high.Hosts["host-a"].History[1] = "changed"
	s.state.Hosts["host-a"].History[1] = "changed too"
	clear(current.Bytes)
	if !refusal.Is(snapshot.Authorize("host-a", "legacy.dev"), refusal.NameNotPermitted) {
		t.Fatal("aliased snapshot")
	}
	copy, _ = snapshot.Current("host-a")
	if len(copy.Keys) != 1 {
		t.Fatal("aliased key windows")
	}
}

// Every failing phase leaves prior objects and durable state intact, and never returns fallback authority.
func TestEveryPhaseFailureIsAtomic(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Input, *store)
		code refusal.Code
	}{
		{"prerequisite", func(in *Input, s *store) { in.Reconciled = false }, refusal.RegistryUnavailable},
		{"phase one", func(in *Input, s *store) { in.Entries[1].Bytes = []byte(`{`) }, refusal.EnrollmentMalformed},
		{"phase two", func(in *Input, s *store) {
			b := record("host-a", 2, 2, "active")
			b["sigs"] = nil
			in.Entries[1] = entry(t, in.Entries[1].Path, b, 1)
		}, refusal.EnrollmentSigsUnsupported},
		{"phase three", func(in *Input, s *store) {
			b := record("host-a", 2, 2, "active")
			b["state"] = "invalid"
			in.Entries[1] = entry(t, in.Entries[1].Path, b, 1)
		}, refusal.EnrollmentMalformed},
		{"phase four", func(in *Input, s *store) {
			raw := in.Entries[1].Bytes
			at := bytes.Index(raw, []byte("sha256:")) + 7
			if raw[at] == '0' {
				raw[at] = '1'
			} else {
				raw[at] = '0'
			}
		}, refusal.EnrollmentIDMismatch},
		{"phase five", func(in *Input, s *store) {
			in.Entries[1] = entry(t, in.Entries[1].Path, record("host-a", 2, 2, "active"), 3)
		}, refusal.EnrollmentSignatureInvalid},
		{"phase six", func(in *Input, s *store) {
			in.Entries[1] = entry(t, in.Entries[1].Path, record("host-b", 1, 2, "active"), 1)
		}, refusal.RegistryConflict},
		{"phase seven", func(in *Input, s *store) { in.Entries = in.Entries[1:] }, refusal.RegistryRollback},
		{"persistence", func(in *Input, s *store) { s.fail = true }, refusal.RegistryUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, _, s := loader(t)
			old := entry(t, "enrollments/a.json", record("host-a", 1, 2, "active", "legacy.dev"), 1)
			previous, retained := bootstrap(t, l, old)
			before := retained.Clone()
			in := Input{Revision: revB, Retained: retained, Reconciled: true, Entries: []Entry{old, entry(t, "enrollments/b.json", record("host-a", 2, 2, "active"), 1)}}
			tc.edit(&in, s)
			snapshot, next, err := l.Load(in)
			if !refusal.Is(err, tc.code) || snapshot != nil || next != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, retained) || !reflect.DeepEqual(before, s.state) {
				t.Fatal("state changed")
			}
			if err := previous.Authorize("host-a", "legacy.dev"); err != nil {
				t.Fatal(err)
			}
			s.fail = false
			in.Entries = []Entry{old}
			in.Reconciled = true
			if _, _, err = l.Load(in); err != nil {
				t.Fatal("valid retry", err)
			}
		})
	}
}

// Git-path ordering is unsigned-byte order; ignored tree paths neither count toward caps nor become enrollment authority.
func TestPathsAndFiltering(t *testing.T) {
	l, v, _ := loader(t)
	entries := []Entry{entry(t, "enrollments/😀.json", record("host-a", 3, 2, "active"), 1), {Path: "notes/ignored.json", Bytes: []byte(`{`), Kind: Symlink}, entry(t, "enrollments/\ue000.json", record("host-a", 2, 2, "active"), 1), entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1), {Path: "enrollments/nested/ignored.json", Kind: Other}}
	snapshot, _ := bootstrap(t, l, entries...)
	if !reflect.DeepEqual(v.seen, []string{"enrollments/a.json", "enrollments/\ue000.json", "enrollments/😀.json"}) {
		t.Fatal(v.seen)
	}
	current, _ := snapshot.Current("host-a")
	if current.Seq != 3 {
		t.Fatal("path selected authority")
	}
	l, _, _ = loader(t)
	badA := Entry{Path: "enrollments/a.json", Bytes: []byte(`{`)}
	badZ := Entry{Path: "enrollments/z.json", Bytes: []byte(`{`)}
	verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{badZ, badA}}, refusal.EnrollmentMalformed, badA.Path)
	l, _, _ = loader(t)
	huge := entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)
	huge.Bytes = append(huge.Bytes, bytes.Repeat([]byte(" "), 65537-len(huge.Bytes))...)
	verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{huge}}, refusal.EnrollmentMalformed, huge.Path)
	if !strings.HasPrefix(snapshot.Revision(), "1111") {
		t.Fatal("revision")
	}
}

// Every adjacent document phase outranks later defects even when its failing file sorts last.
func TestAdjacentDocumentPhasePrecedence(t *testing.T) {
	cases := []struct {
		name    string
		earlier func(Entry) Entry
		later   func(Entry) Entry
		code    refusal.Code
	}{
		{"shape before reserved", func(e Entry) Entry { e.Bytes = []byte(`{`); return e }, func(e Entry) Entry {
			b := record("host-b", 1, 4, "active")
			b["sigs"] = nil
			return entry(t, e.Path, b, 1)
		}, refusal.EnrollmentMalformed},
		{"reserved before schema", func(e Entry) Entry {
			b := record("host-a", 1, 2, "active")
			b["sigs"] = nil
			return entry(t, e.Path, b, 1)
		}, func(e Entry) Entry {
			b := record("host-b", 1, 4, "active")
			b["state"] = "invalid"
			return entry(t, e.Path, b, 1)
		}, refusal.EnrollmentSigsUnsupported},
		{"schema before id", func(e Entry) Entry {
			b := record("host-a", 1, 2, "active")
			b["state"] = "invalid"
			return entry(t, e.Path, b, 1)
		}, func(e Entry) Entry {
			e.Bytes = bytes.Clone(e.Bytes)
			at := bytes.Index(e.Bytes, []byte("sha256:")) + 7
			if e.Bytes[at] == 'f' {
				e.Bytes[at] = '0'
			} else {
				e.Bytes[at] = 'f'
			}
			return e
		}, refusal.EnrollmentMalformed},
		{"id before signature", func(e Entry) Entry {
			e.Bytes = bytes.Clone(e.Bytes)
			at := bytes.Index(e.Bytes, []byte("sha256:")) + 7
			if e.Bytes[at] == 'f' {
				e.Bytes[at] = '0'
			} else {
				e.Bytes[at] = 'f'
			}
			return e
		}, func(e Entry) Entry { return entry(t, e.Path, record("host-b", 1, 4, "active"), 3) }, refusal.EnrollmentIDMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				l, _, _ := loader(t)
				a, z := "enrollments/z.json", "enrollments/a.json"
				if reverse {
					a, z = z, a
				}
				early := entry(t, a, record("host-a", 1, 2, "active"), 1)
				late := entry(t, z, record("host-b", 1, 4, "active"), 1)
				verdict(t, l, Input{Revision: revA, FirstUse: true, Entries: []Entry{tc.later(late), tc.earlier(early)}}, tc.code, a)
				bootstrap(t, l, early, entry(t, z, record("host-b", 1, 4, "active"), 1))
			}
		})
	}
}

// Retained ownership attribution survives an omitted file and wins as conflict before the history-omission rollback.
func TestRetainedClaimsBeforeOmission(t *testing.T) {
	for _, keyReuse := range []bool{false, true} {
		l, _, s := loader(t)
		old := entry(t, "enrollments/a.json", record("host-a", 1, 2, "revoked", "legacy.dev"), 1)
		previous, retained := bootstrap(t, l, old)
		before := retained.Clone()
		key := byte(4)
		explicit := []string{"legacy.dev"}
		if keyReuse {
			key = 2
			explicit = nil
		}
		candidate := entry(t, "enrollments/b.json", record("host-b", 1, key, "active", explicit...), 1)
		verdict(t, l, Input{Revision: revB, Entries: []Entry{candidate}, Retained: retained, Reconciled: true}, refusal.RegistryConflict, candidate.Path)
		if !reflect.DeepEqual(s.state, before) {
			t.Fatal("durable state changed")
		}
		if !refusal.Is(previous.Authorize("host-a", "host-a_project_role"), refusal.HostRevoked) {
			t.Fatal("tombstone authority")
		}
		if _, _, err := l.Load(Input{Revision: revB, Entries: []Entry{old}, Retained: retained, Reconciled: true}); err != nil {
			t.Fatal(err)
		}
	}
}

// Prerequisite caps are inclusive; this helper test does not claim malformed payloads are installable documents.
func TestAggregateCapBoundaries(t *testing.T) {
	entries := make([]Entry, MaxEntries)
	for i := range entries {
		entries[i] = Entry{Path: fmt.Sprintf("enrollments/%05d.json", i), Kind: Regular}
	}
	if _, err := prepareEntries(append(entries, Entry{Path: "enrollments/extra.json"})); !refusal.Is(err, refusal.RegistryUnavailable) {
		t.Fatal(err)
	}
	if _, err := prepareEntries(entries); err != nil {
		t.Fatal(err)
	}
	full := []Entry{{Path: "enrollments/a.json", Bytes: make([]byte, MaxBytes/2)}, {Path: "enrollments/b.json", Bytes: make([]byte, MaxBytes/2)}}
	if _, err := prepareEntries(append(full, Entry{Path: "enrollments/c.json", Bytes: []byte{1}})); !refusal.Is(err, refusal.RegistryUnavailable) {
		t.Fatal(err)
	}
	if _, err := prepareEntries(full); err != nil {
		t.Fatal(err)
	}
}

// Missing/corrupt freshness or dependencies cannot be treated as first use; unavailable ancestry and stale persistence fail closed.
func TestRetainedEvidenceAndDependencies(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Input, *Loader, *verifier, *store)
	}{
		{"unreconciled", func(in *Input, l *Loader, v *verifier, s *store) { in.Reconciled = false }},
		{"lost high water", func(in *Input, l *Loader, v *verifier, s *store) { in.Retained = nil }},
		{"bootstrap over retained", func(in *Input, l *Loader, v *verifier, s *store) { in.FirstUse = true }},
		{"history missing", func(in *Input, l *Loader, v *verifier, s *store) {
			w := in.Retained.Hosts["host-a"]
			w.History = nil
			in.Retained.Hosts["host-a"] = w
		}},
		{"ownership evidence missing", func(in *Input, l *Loader, v *verifier, s *store) { in.Retained.KeyOwners = nil }},
		{"ancestry unavailable", func(in *Input, l *Loader, v *verifier, s *store) { v.ancestryError = true }},
		{"no store", func(in *Input, l *Loader, v *verifier, s *store) { l.Store = nil }},
		{"no verifier", func(in *Input, l *Loader, v *verifier, s *store) { l.Verifier = nil }},
		{"no policy", func(in *Input, l *Loader, v *verifier, s *store) { l.Policy = nil }},
		{"stale store compare", func(in *Input, l *Loader, v *verifier, s *store) { s.state.Revision = strings.Repeat("3", 40) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, v, s := loader(t)
			original := entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)
			_, retained := bootstrap(t, l, original)
			in := Input{Revision: revB, Retained: retained.Clone(), Reconciled: true, Entries: []Entry{original}}
			tc.edit(&in, &l, v, s)
			stateBefore := s.state.Clone()
			waterBefore := in.Retained.Clone()
			snapshot, next, err := l.Load(in)
			if !refusal.Is(err, refusal.RegistryUnavailable) || snapshot != nil || next != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(waterBefore, in.Retained) || !reflect.DeepEqual(stateBefore, s.state) {
				t.Fatal("evidence mutated")
			}
			l, _, _ = loader(t)
			bootstrap(t, l, original)
		})
	}
}

// Publisher rotation may change signatures but never IDs; host-key rotation changes current keys while retained attribution persists.
func TestPublisherAndHostKeyRotation(t *testing.T) {
	l, _, s := loader(t)
	oldBody := record("host-a", 1, 2, "active")
	old := entry(t, "enrollments/old.json", oldBody, 1)
	_, retained := bootstrap(t, l, old)
	p, err := enrollment.NewPolicy("example.org", testPublic(3), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	l.Policy = p
	snapshot, next, err := l.Load(Input{Revision: revB, Retained: retained, Reconciled: true, Entries: []Entry{entry(t, old.Path, oldBody, 3), entry(t, "enrollments/new.json", record("host-a", 2, 4, "active"), 3)}})
	if err != nil {
		t.Fatal(err)
	}
	current, _ := snapshot.Current("host-a")
	if len(current.Keys) != 1 || current.Keys[0].Key.Encoding() != testPublic(4) || next.Hosts["host-a"].History[1] != retained.Hosts["host-a"].ID || next.KeyOwners[testPublic(2)] != "host-a" || s.calls != 2 {
		t.Fatal("rotation changed history/currentness")
	}
	// A retained tombstone blocks new active records even when that tombstone's file is omitted.
	l, _, _ = loader(t)
	tombstone := entry(t, "enrollments/old.json", record("host-a", 1, 2, "revoked"), 1)
	_, retained = bootstrap(t, l, tombstone)
	active := entry(t, "enrollments/new.json", record("host-a", 2, 2, "active"), 1)
	verdict(t, l, Input{Revision: revB, Retained: retained, Reconciled: true, Entries: []Entry{active}}, refusal.RegistryRollback, active.Path)
}

// Snapshot authorization preserves the structured/legacy union without treating a matching prefix or unknown host as authority.
func TestSnapshotLeadingHyphenNamespace(t *testing.T) {
	l, _, _ := loader(t)
	snapshot, _ := bootstrap(t, l, entry(t, "enrollments/a.json", record("-node", 1, 2, "active"), 1))
	if err := snapshot.Authorize("-node", "-node_project_role"); err != nil {
		t.Fatal(err)
	}
	if !refusal.Is(snapshot.Authorize("-node", "-legacy"), refusal.NameInvalid) {
		t.Fatal("syntax")
	}
	if !refusal.Is(snapshot.Authorize("-node", "node_project_role"), refusal.NameNotPermitted) {
		t.Fatal("foreign namespace")
	}
	if !refusal.Is(snapshot.Authorize("absent", "legacy.dev"), refusal.NameNotPermitted) {
		t.Fatal("unknown host")
	}
}
