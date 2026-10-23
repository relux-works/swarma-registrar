package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	public "github.com/relux-works/swarma-registrar/registration"
)

// A public-built, self-verified proof still needs admission authority: wrong
// audience is refused with no JWT, then the same key/name/nonce succeeds at
// capacity one. The existing exact JWT/audit oracle checks the issued result.
// All adapters are the existing in-memory fixtures, with no listener or network.
func TestPublicRegistrationAdmission(t *testing.T) {
	f := setup(t)
	proof := func(audience string) []byte {
		t.Helper()
		body, pre, err := public.Build(public.Body{Key: testPublic(2), Name: "host-a_project_role", Audience: audience, Nonce: bytes.Repeat([]byte{1}, 16), IssuedAt: "2030-01-01T00:01:40Z", ExpiresAt: "2030-01-01T00:02:00Z"}, "example.org")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := public.Assemble(body, ed25519.Sign(testPrivate(2), pre))
		if err != nil {
			t.Fatal(err)
		}
		checked, err := public.Verify(raw)
		if err != nil || checked == nil || checked.Audience != audience {
			t.Fatalf("self-check: %v %v", checked, err)
		}
		return raw
	}
	bad := proof("other.example")
	rejected(t, serve(t, f, request(bad)), "audience_mismatch", 403)
	events := f.audit.events(t)
	if len(events) != 1 || events[0]["code"] != "audience_mismatch" || events[0]["outcome"] != "refused" {
		t.Fatal(events)
	}
	accepted(t, f, proof("example.org"))
	if len(f.audit.lines) != 2 {
		t.Fatalf("unexpected audit writes: %d", len(f.audit.lines))
	}
}
