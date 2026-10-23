package registration_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/relux-works/swarma-registrar/registration"
)

func ExampleBuild() {
	// RFC 8032 §7.1 test 1's published seed is for examples only.
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	private := ed25519.NewKeyFromSeed(seed) // The caller owns signing, outside the package.
	input := registration.Body{Key: "ed25519:" + base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Name: "host-a_project_role", Audience: "example.org", Nonce: make([]byte, 16), IssuedAt: "2030-01-01T00:01:40Z", ExpiresAt: "2030-01-01T00:02:00Z"}
	// Production callers generate a fresh nonce with a CSPRNG for each attempt.
	body, preimage, err := registration.Build(input, "example.org")
	if err != nil {
		panic(err)
	}
	proof, err := registration.Assemble(body, ed25519.Sign(private, preimage))
	if err != nil {
		panic(err)
	}
	verified, err := registration.Verify(proof)
	if err != nil {
		panic(err)
	}
	fmt.Println(verified.Name)
	// Output: host-a_project_role
}
