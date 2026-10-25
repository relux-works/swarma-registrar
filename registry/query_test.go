package registry_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/registry"
	"testing"
)

func queryPublic(seed byte) string {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
}
func queryEntry(t *testing.T, path string, seq int64, key byte, state string) registry.Entry {
	t.Helper()
	body := map[string]any{"type": "enrollment/1", "host": "host-a", "seq": seq, "state": state,
		"keys":    []any{map[string]any{"key": queryPublic(key), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}},
		"names":   map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}},
		"uid_map": []any{map[string]any{"uid": int64(1), "names": []any{"legacy.dev"}, "exe": "/bin/client"}},
	}
	pre, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pre))}, ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return registry.Entry{Path: path, Bytes: raw}
}

// Lookup is exact and current-only, including tombstones/expired windows as data.
// Public accessors cannot mutate verified records or turn historical keys into authority.
func TestCurrentKeyLookupAndCopies(t *testing.T) {
	for _, state := range []string{"active", "revoked"} {
		t.Run(state, func(t *testing.T) {
			policy, err := enrollment.NewPolicy("example.org", queryPublic(1), map[string]bool{"host-a": true})
			if err != nil {
				t.Fatal(err)
			}
			entries := []registry.Entry{queryEntry(t, "enrollments/a.json", 1, 2, "active"), queryEntry(t, "enrollments/b.json", 2, 3, state)}
			revision := "1111111111111111111111111111111111111111"
			store := &fixtureStore{}
			loader := registry.Loader{ObjectFormat: "sha1", Policy: policy, Verifier: fixtureVerifier{revision, entries}, Store: store}
			snapshot, high, err := loader.Load(registry.Input{Revision: revision, Entries: entries, FirstUse: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{queryPublic(2), "bad", queryPublic(3) + "="} {
				if r, w, found := snapshot.LookupKey(key); found || r != nil || w != (enrollment.Window{}) {
					t.Fatal("noncurrent/nonexact key matched")
				}
			}
			if r, found := snapshot.Current("host-b"); found || r != nil {
				t.Fatal("unknown host")
			}
			r, w, found := snapshot.LookupKey(queryPublic(3))
			if !found || r.Host() != "host-a" || r.Sequence() != 2 || r.Revoked() != (state == "revoked") || !w.ValidAt(w.NotBefore, w.NotBefore) || w.ValidAt(w.NotBefore, w.NotAfter) {
				t.Fatal("current key view")
			}
			current, _ := snapshot.Current("host-a")
			if current.ID() != r.ID() || len(current.CanonicalBody()) == 0 || snapshot.Revision() != revision {
				t.Fatal("current record")
			}
			keys := r.Keys()
			keys[0].Key = "bad"
			uid := r.UIDMap()
			uid[0].Names[0] = "changed"
			*uid[0].Exe = "/changed"
			prefix, names := r.Names()
			names[0] = "changed"
			canonical := r.CanonicalBody()
			clear(canonical)
			high.Hosts["host-a"].History[2] = "changed"
			high.KeyOwners[queryPublic(2)] = "host-b"
			clear(entries[1].Bytes)
			if r.Keys()[0].Key != queryPublic(3) || r.UIDMap()[0].Names[0] != "legacy.dev" || *r.UIDMap()[0].Exe != "/bin/client" || prefix != "host-a_" || bytes.Equal(r.CanonicalBody(), canonical) {
				t.Fatal("aliased public data")
			}
			if err := r.Permits("legacy.dev", policy.Audience()); err != nil {
				t.Fatal(err)
			}
			err = snapshot.Authorize("host-a", "host-a_project_role")
			var refusal *registry.Error
			if state == "revoked" {
				if !errors.As(err, &refusal) || refusal.Code != registry.HostRevoked {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if _, _, found := snapshot.LookupKey(queryPublic(3)); !found {
				t.Fatal("query index mutated")
			}
			if r, _, found := snapshot.LookupKey(queryPublic(2)); found || r != nil {
				t.Fatal("historical key gained authority")
			}
			// Core parsing rejects corrupted input; no public snapshot/state can escape.
			candidate, next, err := loader.Load(registry.Input{Revision: revision, Entries: entries, Retained: store.state.Clone(), Reconciled: true})
			var diagnostic *registry.Diagnostic
			if candidate != nil || next != nil || !errors.As(err, &diagnostic) || diagnostic.Code != registry.EnrollmentMalformed || diagnostic.Path != "enrollments/b.json" {
				t.Fatalf("failed reload: %v", err)
			}
			// The caller fences admission after failure; retained objects are recovery evidence.
		})
	}
}

// A missing policy remains unavailable through both public entrypoints; a valid
// policy/record control prevents a facade that refuses every call from passing.
func TestMissingPolicyAndValidControl(t *testing.T) {
	var policy *enrollment.Policy
	raw := queryEntry(t, "enrollments/a.json", 1, 2, "active").Bytes
	r, err := policy.Parse(raw)
	var refusal *enrollment.Error
	if r != nil || !errors.As(err, &refusal) || refusal.Code != enrollment.RegistryUnavailable {
		t.Fatal(err)
	}
	loader := registry.Loader{ObjectFormat: "sha1", Verifier: fixtureVerifier{}, Store: &fixtureStore{}}
	s, h, err := loader.Load(registry.Input{Revision: "1111111111111111111111111111111111111111", FirstUse: true})
	if s != nil || h != nil || !errors.As(err, &refusal) || refusal.Code != registry.RegistryUnavailable {
		t.Fatal(err)
	}
	policy, err = enrollment.NewPolicy("example.org", queryPublic(1), map[string]bool{"host-a": true})
	if err != nil {
		t.Fatal(err)
	}
	r, err = policy.Parse(raw)
	if err != nil || r.Host() != "host-a" || r.Sequence() != 1 {
		t.Fatal("positive control", err)
	}
}
