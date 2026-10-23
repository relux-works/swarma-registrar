package conformance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/registry"
)

// These adapters provide external trust/durability outcomes, never validation.
// The explicit registry-bootstrap / registry-reload row classifications are
// caller/operator decisions. Missing retained state never selects first use.
// Legacy bootstrap rows omit first_use; their classification supplies that
// explicit approval. A present fixture approval must agree with the caller.
// Prior snapshots have independently approved pins and successful persistence;
// candidate trust/persistence faults apply only to the attempted reload.
type fixtureVerifier struct {
	revision, previous   string
	entries              []registry.Entry
	approved, descendant bool
}

func (f fixtureVerifier) Verify(revision string, entries []registry.Entry) error {
	// Commit identity is independent of caller enumeration order; the loader
	// must present the complete entry set in byte-path order.
	want := append([]registry.Entry(nil), f.entries...)
	sort.Slice(want, func(i, j int) bool { return want[i].Path < want[j].Path })
	if !f.approved || revision != f.revision || !reflect.DeepEqual(entries, want) {
		return fmt.Errorf("entry set differs from fixture-approved revision")
	}
	return nil
}

func (f fixtureVerifier) Descends(candidate, previous string) (bool, error) {
	if candidate != f.revision || previous != f.previous {
		return false, fmt.Errorf("ancestry query differs from fixture revisions")
	}
	return f.descendant, nil
}

type fixtureStore struct {
	available bool
	calls     int
	state     *registry.HighWater
}

func (f *fixtureStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	f.calls++
	if !f.available || !reflect.DeepEqual(previous, f.state) {
		return fmt.Errorf("fixture store unavailable or stale prior state")
	}
	f.state = next.Clone()
	return nil
}

func fixtureEntries(files []registryFile) ([]registry.Entry, error) {
	entries := make([]registry.Entry, 0)
	for _, file := range files {
		data, err := base64.RawURLEncoding.Strict().DecodeString(file.Bytes)
		if err != nil || base64.RawURLEncoding.EncodeToString(data) != file.Bytes || file.Repeat < 1 {
			return nil, fmt.Errorf("invalid registry fixture bytes or repeat count")
		}
		var kind registry.EntryKind
		switch file.Kind {
		case "regular":
			kind = registry.Regular
		case "symlink":
			kind = registry.Symlink
		case "other":
			kind = registry.Other
		default:
			return nil, fmt.Errorf("unknown registry fixture entry kind %q", file.Kind)
		}
		for i := 0; i < file.Repeat; i++ {
			path := file.Path
			if file.PathTemplate != "" {
				path = fmt.Sprintf(file.PathTemplate, i)
			}
			entries = append(entries, registry.Entry{Path: path, Kind: kind, Bytes: append([]byte(nil), data...)})
		}
	}
	// Preserve fixture enumeration order. The loader sorts its own input;
	// no entry is filtered, repaired, decoded as enrollment or validated here.
	return entries, nil
}

func fixturePolicy(v vector, publisher string) (*enrollment.Policy, error) {
	stations := make(map[string]bool)
	for _, host := range v.Fixture.Registry.NonstationHosts {
		stations[host] = false
	}
	for _, host := range v.Fixture.Registry.StationHosts {
		if _, exists := stations[host]; exists {
			return nil, fmt.Errorf("contradictory host classifications")
		}
		stations[host] = true
	}
	return enrollment.NewPolicy(v.Fixture.Audience, publisher, stations)
}

func exerciseRegistry(v vector, raw []byte, firstUse bool) observation {
	f := v.Fixture.Registry
	fail := func(err error) observation { return observation{setupErr: err, err: err} }
	if f.FirstUse != nil && *f.FirstUse != firstUse {
		return fail(fmt.Errorf("fixture first-use approval contradicts caller mode"))
	}
	entries, err := fixtureEntries(f.Files)
	if err != nil {
		return fail(err)
	}
	if len(entries) == 0 || !bytes.Equal(entries[0].Bytes, raw) {
		return fail(fmt.Errorf("input differs from first candidate entry"))
	}
	var previous *registry.Snapshot
	var retained *registry.HighWater
	if len(f.PreviousFiles) != 0 {
		priorEntries, err := fixtureEntries(f.PreviousFiles)
		if err != nil {
			return fail(err)
		}
		publisher := f.PreviousPublisherKey
		if publisher == "" {
			publisher = f.PublisherKey
		}
		policy, err := fixturePolicy(v, publisher)
		if err != nil {
			return fail(fmt.Errorf("prior policy: %w", err))
		}
		store := &fixtureStore{available: true}
		verifier := fixtureVerifier{revision: f.PreviousRevision, entries: priorEntries, approved: true}
		previous, retained, err = (registry.Loader{Policy: policy, Verifier: verifier, Store: store}).Load(registry.Input{
			Revision: f.PreviousRevision, Entries: priorEntries, FirstUse: true,
		})
		if err != nil || previous == nil || retained == nil || store.calls != 1 || !reflect.DeepEqual(store.state, retained) {
			return fail(fmt.Errorf("prior authority could not be established: %v", err))
		}
	}
	if firstUse && retained != nil {
		return fail(fmt.Errorf("bootstrap row unexpectedly has prior authority"))
	}
	store := &fixtureStore{available: f.PersistAvailable, state: retained.Clone()}
	out := observation{before: store.state.Clone(), retained: retained, retainedBefore: retained.Clone(), previous: previous}
	policy, err := fixturePolicy(v, f.PublisherKey)
	if err != nil && f.PublisherKey != "" {
		return fail(fmt.Errorf("candidate policy: %w", err))
	}
	// A missing publisher leaves Policy nil: the loader itself diagnoses the
	// missing prerequisite. Lost rollback evidence is never replaced by bootstrap.
	in := registry.Input{Revision: f.Revision, Entries: entries, FirstUse: firstUse,
		Retained: retained, Reconciled: f.RollbackStateAvailable}
	if !f.RollbackStateAvailable {
		in.Retained = nil
	}
	verifier := fixtureVerifier{revision: f.Revision, previous: f.PreviousRevision, entries: entries,
		approved: f.Available && f.Approved && f.CommitSignatureValid && f.PinIsExact, descendant: f.Descendant}
	out.snapshot, out.water, out.err = (registry.Loader{Policy: policy, Verifier: verifier, Store: store}).Load(in)
	out.persisted, out.commits = store.state, store.calls
	return out
}

// Refusals return no candidate authority and preserve prior objects/store state.
// Persistence failure necessarily attempts one CAS; every validation refusal
// must precede the store. Accepts publish exactly the full history/ownership and
// highest-sequence records specified by the candidate, after exactly one CAS.
func assertRegistryObservation(t *testing.T, v vector, got observation) {
	t.Helper()
	if got.setupErr != nil {
		t.Fatalf("registry fixture setup: %v", got.setupErr)
	}
	if !reflect.DeepEqual(got.retained, got.retainedBefore) {
		t.Error("loader mutated retained evidence")
	}
	if got.previous != nil {
		assertAuthority(t, got.previous, got.before, v.Fixture.Registry.PreviousFiles, v.Fixture.Registry.PreviousRevision)
	}
	if got.err != nil {
		var diagnostic *registry.Diagnostic
		if !errors.As(got.err, &diagnostic) {
			t.Error("loader refusal lacks typed registry diagnostic")
		}
		calls := 0
		if !v.Fixture.Registry.PersistAvailable {
			calls = 1
		}
		if got.snapshot != nil || got.water != nil || got.commits != calls || !reflect.DeepEqual(got.persisted, got.before) {
			t.Errorf("refusal changed authority/store or attempted wrong CAS count: calls=%d want=%d", got.commits, calls)
		}
		assertAuthorityIDs(t, got.before, v)
		return
	}
	if got.snapshot == nil || got.water == nil || got.commits != 1 || !reflect.DeepEqual(got.persisted, got.water) {
		t.Fatal("accepted registry candidate missing exactly-once publication")
	}
	assertAuthority(t, got.snapshot, got.water, v.Fixture.Registry.Files, v.Fixture.Registry.Revision)
	assertAuthorityIDs(t, got.water, v)
}

func assertAuthorityIDs(t *testing.T, water *registry.HighWater, v vector) {
	t.Helper()
	ids := make([]string, 0)
	revision := ""
	if water != nil {
		revision = water.Revision
		for _, host := range water.Hosts {
			for _, id := range host.History {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, v.Expected.State.Authority.RecordIDs) || revision != v.Expected.State.Authority.Revision {
		t.Errorf("DISAGREEMENT %s authority: loader ids=%v revision=%q vector ids=%v revision=%q",
			v.Row, ids, revision, v.Expected.State.Authority.RecordIDs, v.Expected.State.Authority.Revision)
	}
}

// This oracle projects already accepted fixture bodies into expected observable
// state. It never decides acceptance or substitutes for any loader phase.
func assertAuthority(t *testing.T, snapshot *registry.Snapshot, water *registry.HighWater, files []registryFile, revision string) {
	t.Helper()
	entries, err := fixtureEntries(files)
	if err != nil {
		t.Fatal(err)
	}
	want := &registry.HighWater{Revision: revision, Hosts: map[string]registry.HostWater{}, KeyOwners: map[string]string{}, NameOwners: map[string]string{}}
	bodies := make(map[string]map[string]any)
	for _, entry := range entries {
		var env struct {
			ID   string
			Body json.RawMessage
		}
		var body struct {
			Host  string
			Seq   int64
			State string
			Keys  []struct{ Key string }
			Names struct{ Explicit []string }
		}
		if err := json.Unmarshal(entry.Bytes, &env); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(env.Body, &body); err != nil {
			t.Fatal(err)
		}
		host := want.Hosts[body.Host]
		if host.History == nil {
			host.History = map[int64]string{}
		}
		host.History[body.Seq] = env.ID
		if body.Seq > host.Seq {
			host.Seq, host.ID, host.Revoked = body.Seq, env.ID, body.State == "revoked"
			var decoded map[string]any
			if err := json.Unmarshal(env.Body, &decoded); err != nil {
				t.Fatal(err)
			}
			bodies[body.Host] = decoded
		}
		want.Hosts[body.Host] = host
		for _, key := range body.Keys {
			want.KeyOwners[key.Key] = body.Host
		}
		for _, name := range body.Names.Explicit {
			want.NameOwners[name] = body.Host
		}
	}
	if !reflect.DeepEqual(water, want) || snapshot.Revision() != revision {
		t.Error("installed history/ownership/revision differs from candidate")
	}
	for host, expected := range want.Hosts {
		current, ok := snapshot.Current(host)
		if !ok || current.ID() != expected.ID || current.Sequence() != expected.Seq || current.Revoked() != expected.Revoked || current.Host() != host {
			t.Errorf("highest-sequence current authority differs for %s", host)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(current.CanonicalBody(), &body); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, bodies[host]) {
			t.Errorf("current body differs for %s", host)
		}
	}
}

// With an unchanged valid descendant as the positive control, each external
// prerequisite must independently fence a reload. Missing evidence cannot be
// reinterpreted as first use; failed persistence may attempt but never install.
func TestRegistryFixtureTrustAndFreshness(t *testing.T) {
	v := loadEnrollmentVector(t, "PE6")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(v.Input.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("valid-descendant", func(t *testing.T) {
		got := exerciseRegistry(v, raw, false)
		if got.err != nil {
			t.Fatal(got.err)
		}
		assertRegistryObservation(t, v, got)
	})
	for _, tc := range []struct {
		name   string
		change func(*registryFixture)
		code   string
		calls  int
	}{
		{"unavailable", func(f *registryFixture) { f.Available = false }, "registry_unavailable", 0},
		{"unapproved", func(f *registryFixture) { f.Approved = false }, "registry_unavailable", 0},
		{"bad-commit-signature", func(f *registryFixture) { f.CommitSignatureValid = false }, "registry_unavailable", 0},
		{"inexact-pin", func(f *registryFixture) { f.PinIsExact = false }, "registry_unavailable", 0},
		{"nondescendant", func(f *registryFixture) { f.Descendant = false }, "registry_rollback", 0},
		{"lost-rollback-evidence", func(f *registryFixture) { f.RollbackStateAvailable = false }, "registry_unavailable", 0},
		{"missing-retained-not-bootstrap", func(f *registryFixture) { f.PreviousFiles = nil; f.PreviousRevision = "" }, "registry_unavailable", 0},
		{"persistence-failure", func(f *registryFixture) { f.PersistAvailable = false }, "registry_unavailable", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := v
			tc.change(&candidate.Fixture.Registry)
			got := exerciseRegistry(candidate, raw, false)
			if got.setupErr != nil {
				t.Fatal(got.setupErr)
			}
			if code := resultCode(got.err); code != tc.code {
				t.Errorf("diagnostic=%s want=%s", code, tc.code)
			}
			if got.snapshot != nil || got.water != nil || got.commits != tc.calls || !reflect.DeepEqual(got.persisted, got.before) || !reflect.DeepEqual(got.retained, got.retainedBefore) {
				t.Errorf("refused reload changed authority or CAS count: calls=%d want=%d", got.commits, tc.calls)
			}
			if got.previous != nil {
				assertAuthority(t, got.previous, got.before, candidate.Fixture.Registry.PreviousFiles, candidate.Fixture.Registry.PreviousRevision)
			}
		})
	}
}

func loadEnrollmentVector(t *testing.T, row string) vector {
	t.Helper()
	root := os.Getenv("CONFORMANCE_VECTORS")
	if root == "" {
		root = filepath.Join("..", "..", "vectors")
	}
	for _, path := range vectorFiles(t, filepath.Join(root, "enrollment-1")) {
		if filepath.Base(path) != row+".json" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var v vector
		if err = json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Fatalf("missing enrollment control %s", row)
	return vector{}
}

// Reversing caller enumeration preserves snapshot-wide diagnostic precedence
// and selected authority. The adapter must not pre-sort away this loader input.
func TestRegistryFixturePathOrder(t *testing.T) {
	for _, row := range []string{"PE4", "E107", "E108", "E109"} {
		t.Run(row, func(t *testing.T) {
			v := loadEnrollmentVector(t, row)
			files := v.Fixture.Registry.Files
			for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
				files[i], files[j] = files[j], files[i]
			}
			raw, err := base64.RawURLEncoding.Strict().DecodeString(files[0].Bytes)
			if err != nil {
				t.Fatal(err)
			}
			got := exerciseRegistry(v, raw, true)
			if code := resultCode(got.err); code != v.Expected.Code {
				t.Errorf("diagnostic=%s want=%s", code, v.Expected.Code)
			}
			assertRegistryObservation(t, v, got)
		})
	}
}
