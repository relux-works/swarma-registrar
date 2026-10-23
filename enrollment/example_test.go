package enrollment_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
)

// Test seeds are fixed and public; production publishers sign offline.
func ExamplePolicy_Parse() {
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	host := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	encode := func(public ed25519.PublicKey) string {
		return "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
	}
	policy, err := enrollment.NewPolicy("example.org", encode(publisher.Public().(ed25519.PublicKey)), map[string]bool{"host-a": false})
	if err != nil {
		panic(err)
	}
	body := map[string]any{
		"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active",
		"keys":  []any{map[string]any{"key": encode(host.Public().(ed25519.PublicKey)), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}},
		"names": map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}},
	}
	preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		panic(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(publisher, preimage))}, ccj.EnrollmentMalformed)
	if err != nil {
		panic(err)
	}
	record, err := policy.Parse(raw)
	if err != nil {
		panic(err)
	}
	window := record.Keys()[0]
	fmt.Println(record.Host(), record.Sequence(), record.Revoked())
	fmt.Println(window.ValidAt(window.NotBefore, window.NotAfter-1), window.ValidAt(window.NotBefore, window.NotAfter))
	fmt.Println(record.Permits("host-a_project_role", policy.Audience()))
	fmt.Println(record.Permits("host-b_project_role", policy.Audience()))
	// Output:
	// host-a 1 false
	// true false
	// <nil>
	// name_not_permitted
}
