// Package sig verifies the strict registration and enrollment signature profiles.
package sig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"

	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Verify validates the selected key before scalars/low-S and the equation.
// Envelope callers enforce the signature wire length before reaching this API.
func Verify(key *keys.Key, preimage, signature []byte, domain envelope.Domain) error {
	invalid := func() error { return refusal.New(domain.SignatureInvalid()) }
	public, err := key.PublicKey()
	if err != nil || len(signature) != 64 {
		return invalid()
	}
	switch key.Algorithm() {
	case keys.Ed25519:
		if !keys.ValidEd25519Point(signature[:32]) {
			return invalid()
		}
		// crypto/ed25519 also enforces canonical S < L and the ordinary equation.
		if !ed25519.Verify(public.(ed25519.PublicKey), preimage, signature) {
			return invalid()
		}
	case keys.P256:
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		n := elliptic.P256().Params().N
		if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
			return invalid()
		}
		half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
		if s.Cmp(half) > 0 {
			return refusal.New(refusal.SignatureHighS)
		}
		digest := sha256.Sum256(preimage)
		if !ecdsa.Verify(public.(*ecdsa.PublicKey), digest[:], r, s) {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}
