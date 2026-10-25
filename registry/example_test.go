package registry_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/registry"
	"reflect"
)

// This verifier binds an already-approved fixed fixture, not a live Git commit.
// A production adapter verifies protected pins and the signed commit as well.
type fixtureVerifier struct {
	revision string
	entries  []registry.Entry
}

func (v fixtureVerifier) Verify(revision string, entries []registry.Entry) error {
	if revision != v.revision || !reflect.DeepEqual(entries, v.entries) {
		return errors.New("unapproved fixture")
	}
	return nil
}
func (v fixtureVerifier) Descends(candidate, previous string) (bool, error) {
	return candidate == previous, nil
}

// This in-memory test store demonstrates compare-and-swap only. A deployment
// must supply durable atomic persistence; this fake provides no crash durability.
type fixtureStore struct{ state *registry.HighWater }

func (s *fixtureStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if !reflect.DeepEqual(previous, s.state) {
		return errors.New("stale state")
	}
	s.state = next.Clone()
	return nil
}

// Fixed public seeds and revision exercise bootstrap without Git or disk access.
func ExampleLoader_Load() {
	private := func(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)) }
	public := func(seed byte) string {
		return "ed25519:" + base64.RawURLEncoding.EncodeToString(private(seed).Public().(ed25519.PublicKey))
	}
	policy, err := enrollment.NewPolicy("example.org", public(1), map[string]bool{"host-a": false})
	if err != nil {
		panic(err)
	}
	sign := func(path string, seq int64, key byte) registry.Entry {
		body := map[string]any{"type": "enrollment/1", "host": "host-a", "seq": seq, "state": "active",
			"keys":  []any{map[string]any{"key": public(key), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}},
			"names": map[string]any{"prefix": "host-a_", "explicit": []any{}},
		}
		preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
		if err != nil {
			panic(err)
		}
		raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private(1), preimage))}, ccj.EnrollmentMalformed)
		if err != nil {
			panic(err)
		}
		return registry.Entry{Path: path, Bytes: raw, Kind: registry.Regular}
	}
	revision := "1111111111111111111111111111111111111111"
	entries := []registry.Entry{sign("enrollments/a.json", int64(1), 2), sign("enrollments/b.json", int64(2), 3)}
	store := &fixtureStore{}
	loader := registry.Loader{ObjectFormat: "sha1", Policy: policy, Verifier: fixtureVerifier{revision, entries}, Store: store}
	snapshot, high, err := loader.Load(registry.Input{Revision: revision, Entries: entries, FirstUse: true})
	if err != nil {
		panic(err)
	}
	current, _ := snapshot.Current("host-a")
	fmt.Println(current.Host(), current.Sequence(), high.Revision == revision)
	_, _, found := snapshot.LookupKey(public(2))
	fmt.Println("historical key:", found)
	owner, window, found := snapshot.LookupKey(public(3))
	fmt.Println(owner.Host(), found, window.ValidAt(window.NotBefore, window.NotBefore))
	fmt.Println(snapshot.Authorize("host-a", "host-a_project_role"))
	fmt.Println(snapshot.Authorize("host-a", "legacy.dev"))
	// Output:
	// host-a 2 true
	// historical key: false
	// host-a true true
	// <nil>
	// name_not_permitted
}
