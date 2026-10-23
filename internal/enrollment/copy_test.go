package enrollment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Public test seeds from RFC 8032 section 7.1, test vectors 1, 2 and 3.
const copyHostSeed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const copyPublisherSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
const copyOtherSeed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"

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
func copyFixture(t *testing.T) (*enrollment.Policy, []byte) {
	t.Helper()
	body := map[string]any{
		"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active",
		"keys":    []any{map[string]any{"key": copyPublic(t, copyHostSeed), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}},
		"names":   map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}},
		"uid_map": []any{map[string]any{"uid": int64(1), "names": []any{"legacy.dev"}, "exe": "/usr/bin/client"}},
	}
	preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(copyPrivate(t, copyPublisherSeed), preimage))}, refusal.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.NewPolicy("example.org", copyPublic(t, copyPublisherSeed), map[string]bool{"host-a": true})
	if err != nil {
		t.Fatal(err)
	}
	return policy, raw
}
func replacementKey(t *testing.T) *keys.Key {
	t.Helper()
	key, err := keys.ParseEnrollment(copyPublic(t, copyOtherSeed))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Whole-Key assignment through a cloned record cannot change its source's signed key or body.
func TestRecordCloneKeyCopyIsolation(t *testing.T) {
	policy, raw := copyFixture(t)
	record, err := policy.Parse(raw)
	if err != nil || record.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) {
		t.Fatal("signed-record positive control", err)
	}
	id, canonical := record.ID, bytes.Clone(record.CanonicalBody)
	clone := record.Clone()
	*clone.Keys[0].Key = *replacementKey(t)
	if clone.Keys[0].Key.Encoding() != copyPublic(t, copyOtherSeed) {
		t.Fatal("whole-Key assignment was not applied")
	}
	if record.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) || record.ID != id || !bytes.Equal(record.CanonicalBody, canonical) {
		t.Fatal("Record.Clone changed the source's signed key through the returned pointer")
	}
}

// A record returned by Verify cannot replace the key cached in the verified document.
func TestDocumentVerifyKeyCopyIsolation(t *testing.T) {
	policy, raw := copyFixture(t)
	document, err := policy.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := document.CheckBody(); err != nil {
		t.Fatal(err)
	}
	first, err := document.Verify()
	if err != nil || first.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) {
		t.Fatal("first verification positive control", err)
	}
	id, canonical := first.ID, bytes.Clone(first.CanonicalBody)
	*first.Keys[0].Key = *replacementKey(t)
	again, err := document.Verify()
	if err != nil {
		t.Fatal("repeated verification", err)
	}
	if again.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) || again.ID != id || !bytes.Equal(again.CanonicalBody, canonical) {
		t.Fatal("Document.Verify returned an unsigned replacement key after caller mutation")
	}
}

// Decode captures policy inputs: later whole-Policy assignment cannot change a
// document's station classification or pinned publisher, before or after verification.
func TestDocumentPolicyCopyIsolation(t *testing.T) {
	for _, phase := range []string{"before-body", "after-verify"} {
		t.Run(phase, func(t *testing.T) {
			policy, raw := copyFixture(t)
			if _, err := policy.Parse(raw); err != nil {
				t.Fatal("original policy positive control", err)
			}
			document, err := policy.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "after-verify" {
				if err := document.CheckBody(); err != nil {
					t.Fatal(err)
				}
				if _, err := document.Verify(); err != nil {
					t.Fatal(err)
				}
			}
			other, err := enrollment.NewPolicy("other.example.org", copyPublic(t, copyOtherSeed), nil)
			if err != nil {
				t.Fatal(err)
			}
			*policy = *other
			if policy.Audience() != "other.example.org" {
				t.Fatal("whole-Policy assignment was not applied")
			}
			if phase == "before-body" {
				if err := document.CheckBody(); err != nil {
					t.Fatalf("decoded document's station policy changed through caller alias: %v", err)
				}
			}
			record, err := document.Verify()
			if err != nil {
				t.Fatalf("decoded document's pinned publisher changed through caller alias: %v", err)
			}
			if record.Keys[0].Key.Encoding() != copyPublic(t, copyHostSeed) {
				t.Fatal("original signed key changed")
			}
		})
	}
}
