package registry_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registry"
)

// Public test seeds from RFC 8032 section 7.1, test vectors 1, 2 and 3.
const copyHostSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const copyPublisherSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
const copyOtherSeed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
const copyRevision = "1111111111111111111111111111111111111111"

func copyPrivate(t *testing.T, seed string) ed25519.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		t.Fatal("invalid public test seed")
	}
	return ed25519.NewKeyFromSeed(raw)
}
func copyPublic(t *testing.T, seed string) string {
	t.Helper()
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(copyPrivate(t, seed).Public().(ed25519.PublicKey))
}

// These adapters accept only the one bootstrap fixture. They do not qualify
// real Git verification, ancestry or durable persistence implementations.
type copyVerifier struct{ raw []byte }

func (v copyVerifier) Verify(revision string, entries []registry.Entry) error {
	if revision != copyRevision || len(entries) != 1 || entries[0].Path != "enrollments/host-a.json" || entries[0].Kind != registry.Regular || !bytes.Equal(entries[0].Bytes, v.raw) {
		return fmt.Errorf("not the approved test snapshot")
	}
	return nil
}
func (copyVerifier) Descends(string, string) (bool, error) {
	return false, fmt.Errorf("bootstrap fixture has no ancestry query")
}

type copyStore struct{}

func (copyStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if previous != nil || next.Revision != copyRevision {
		return fmt.Errorf("not the test bootstrap state")
	}
	return nil
}

// Whole-Key assignment through Current's returned record cannot replace a
// snapshot's verified key while leaving its signed ID/canonical body unchanged.
func TestSnapshotCurrentKeyCopyIsolation(t *testing.T) {
	body := map[string]any{
		"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active",
		"keys":  []any{map[string]any{"key": copyPublic(t, copyHostSeed), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}},
		"names": map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}},
	}
	preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(copyPrivate(t, copyPublisherSeed), preimage))}, refusal.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.NewPolicy("example.org", copyPublic(t, copyPublisherSeed), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	loader := registry.Loader{Policy: policy, Verifier: copyVerifier{bytes.Clone(raw)}, Store: copyStore{}}
	snapshot, _, err := loader.Load(registry.Input{Revision: copyRevision, Entries: []registry.Entry{{Path: "enrollments/host-a.json", Bytes: raw}}, FirstUse: true})
	if err != nil {
		t.Fatal("signed-load positive control", err)
	}
	first, ok := snapshot.Current("host-a")
	if !ok || first.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) || first.ID != id {
		t.Fatal("original key/id positive control")
	}
	canonical := bytes.Clone(first.CanonicalBody)
	other, err := keys.ParseEnrollment(copyPublic(t, copyOtherSeed))
	if err != nil {
		t.Fatal(err)
	}
	*first.Keys[0].Key = *other
	if first.Keys[0].Key.Encoding() != other.Encoding() {
		t.Fatal("whole-Key assignment was not applied")
	}
	again, ok := snapshot.Current("host-a")
	if !ok || again.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) || again.ID != id || !bytes.Equal(again.CanonicalBody, canonical) {
		t.Fatal("Snapshot.Current returned an unsigned replacement key after caller mutation")
	}
}
