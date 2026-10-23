// Package keys separates schema-time key lexemes from deferred point validation.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"strings"

	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

type Algorithm uint8

const (
	Ed25519 Algorithm = iota + 1
	P256
)

type Key struct {
	algorithm Algorithm
	raw       []byte
	encoding  string
}

func (k *Key) Algorithm() Algorithm { return k.algorithm }
func (k *Key) Encoding() string     { return k.encoding }
func (k *Key) Bytes() []byte        { return append([]byte(nil), k.raw...) }

// Clone returns an independent key object and raw-byte backing storage.
func (k *Key) Clone() *Key {
	if k == nil {
		return nil
	}
	out := *k
	out.raw = append([]byte(nil), k.raw...)
	return &out
}

// Parse performs only the wire checks; recognized bad lengths/points must reach row 7a.
func Parse(text string, malformed refusal.Code) (*Key, error) {
	fail := func() (*Key, error) { return nil, refusal.New(malformed) }
	if len(text) > 128 {
		return fail()
	}
	var alg Algorithm
	var suffix string
	switch {
	case strings.HasPrefix(text, "ed25519:"):
		alg = Ed25519
		suffix = text[8:]
	case strings.HasPrefix(text, "p256:"):
		alg = P256
		suffix = text[5:]
	default:
		return fail()
	}
	raw, ok := envelope.DecodeBase64URL(suffix)
	if !ok {
		return fail()
	}
	return &Key{algorithm: alg, raw: raw, encoding: text}, nil
}

// PublicKey validates the algorithm selected by the prefix, without algorithm fallback.
// Registration point defects are signature-invalid; enrollment callers must map
// these data defects to enrollment_malformed before checking envelope signatures.
func (k *Key) PublicKey() (crypto.PublicKey, error) {
	if k == nil {
		return nil, refusal.New(refusal.RegistrationSignatureInvalid)
	}
	switch k.algorithm {
	case Ed25519:
		if ValidEd25519Point(k.raw) {
			return ed25519.PublicKey(append([]byte(nil), k.raw...)), nil
		}
	case P256:
		if len(k.raw) == 33 && (k.raw[0] == 2 || k.raw[0] == 3) {
			x, y := elliptic.UnmarshalCompressed(elliptic.P256(), k.raw)
			if x != nil && y != nil {
				return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
			}
		}
	}
	return nil, refusal.New(refusal.RegistrationSignatureInvalid)
}

// ParseEnrollment validates enrollment key data, where point defects are malformed.
func ParseEnrollment(text string) (*Key, error) {
	k, err := Parse(text, refusal.EnrollmentMalformed)
	if err != nil {
		return nil, err
	}
	if _, err = k.PublicKey(); err != nil {
		return nil, refusal.New(refusal.EnrollmentMalformed)
	}
	return k, nil
}
