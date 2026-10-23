package envelope_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/envelope"
)

// This published fixed seed is test data, never a deployment signing key.
// Generic envelope verification does not establish enrollment body validity.
func ExampleVerify() {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	public := "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	body := map[string]any{"message": "example"}
	preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		panic(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, preimage))}, ccj.EnrollmentMalformed)
	if err != nil {
		panic(err)
	}
	parsed, err := envelope.Parse(raw, envelope.Enrollment)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed.CheckID() == nil)
	verified, err := envelope.Verify(raw, envelope.Enrollment, public)
	if err != nil {
		panic(err)
	}
	fmt.Println(verified.Body["message"])
	_, err = envelope.Verify(raw, envelope.Registration, public)
	fmt.Println(err)
	// Output:
	// true
	// example
	// registration_id_mismatch
}
