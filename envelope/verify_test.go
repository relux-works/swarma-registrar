package envelope_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/envelope"
	"testing"
)

// Fresh generic verification preserves domain separation, ID-before-key ordering,
// strict pinned-key verification and typed refusals; it does not assert body schema.
func TestVerifyDomainsAndRefusals(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	public := func(key ed25519.PrivateKey) string {
		return "ed25519:" + base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	for _, domain := range []envelope.Domain{envelope.Enrollment, envelope.Registration} {
		pre, id, err := envelope.SigningInput(domain, map[string]any{"example": int64(1)})
		if err != nil {
			t.Fatal(err)
		}
		wire := func(id string, signer ed25519.PrivateKey) []byte {
			raw, err := ccj.Marshal(map[string]any{"body": map[string]any{"example": int64(1)}, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(signer, pre))}, domain.Malformed())
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		mismatch := envelope.EnrollmentIDMismatch
		if domain == envelope.Registration {
			mismatch = envelope.RegistrationIDMismatch
		}
		cases := []struct {
			raw  []byte
			key  string
			code envelope.Code
		}{
			{[]byte(`{`), public(private), domain.Malformed()},
			{wire("sha256:"+string(bytes.Repeat([]byte{'0'}, 64)), private), "bad", mismatch},
			{wire(id, foreign), public(private), domain.SignatureInvalid()},
			{wire(id, private), "bad", domain.Malformed()},
			{wire(id, private), "ed25519:AA", domain.SignatureInvalid()},
		}
		for _, tc := range cases {
			result, err := envelope.Verify(tc.raw, domain, tc.key)
			var refusal *envelope.Error
			if result != nil || !errors.As(err, &refusal) || refusal.Code != tc.code {
				t.Fatalf("%s: result=%v error=%v", domain, result, err)
			}
			if result, err = envelope.Verify(wire(id, private), domain, public(private)); err != nil || result.ID != id {
				t.Fatal("positive control", err)
			}
		}
	}
}
