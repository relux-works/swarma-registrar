package sig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func key(t *testing.T, prefix string, b []byte) *keys.Key {
	t.Helper()
	k, err := keys.Parse(prefix+base64.RawURLEncoding.EncodeToString(b), refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
func le(n *big.Int) []byte {
	b := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// Strict Ed25519 accepts ordinary signatures but refuses noncanonical S, weak R and altered messages in both domains.
func TestEd25519Strict(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	k := key(t, "ed25519:", private.Public().(ed25519.PublicKey))
	message := []byte("public test message")
	valid := ed25519.Sign(private, message)
	// L is the scalar order specified in §3.1; S+L preserves the equation but is not canonical.
	l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	sBytes := bytes.Clone(valid[32:])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		sBytes[i], sBytes[j] = sBytes[j], sBytes[i]
	}
	s := new(big.Int).SetBytes(sBytes)
	noncanonical := bytes.Clone(valid)
	copy(noncanonical[32:], le(new(big.Int).Add(s, l)))
	identityR := bytes.Clone(valid)
	clear(identityR[:32])
	identityR[0] = 1
	smallR := bytes.Clone(valid)
	clear(smallR[:32])
	negativeZeroR := bytes.Clone(identityR)
	negativeZeroR[31] |= 128
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	badR := bytes.Clone(valid)
	copy(badR[:32], le(p))
	y := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), p))
	y.Mod(y, p)
	mixedR := bytes.Clone(valid)
	copy(mixedR[:32], le(new(big.Int).Sub(p, y)))
	mixedR[31] |= 128
	// With nonce scalar zero, R=identity and S=H(R,A,M)*a mod L satisfy
	// the ordinary equation. This witness isolates the required nonidentity-R check.
	expanded := sha512.Sum512(private.Seed())
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	fromLittle := func(raw []byte) *big.Int {
		b := bytes.Clone(raw)
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return new(big.Int).SetBytes(b)
	}
	identityEquation := make([]byte, 64)
	identityEquation[0] = 1
	hInput := append(bytes.Clone(identityEquation[:32]), private.Public().(ed25519.PublicKey)...)
	hInput = append(hInput, message...)
	hDigest := sha512.Sum512(hInput)
	identityS := new(big.Int).Mul(fromLittle(hDigest[:]), fromLittle(expanded[:32]))
	identityS.Mod(identityS, l)
	copy(identityEquation[32:], le(identityS))
	if !ed25519.Verify(private.Public().(ed25519.PublicKey), message, identityEquation) {
		t.Fatal("identity-R equation control is invalid")
	}
	corrupt := bytes.Clone(valid)
	corrupt[40] ^= 1
	for _, domain := range []envelope.Domain{envelope.Registration, envelope.Enrollment} {
		code := refusal.RegistrationSignatureInvalid
		if domain == envelope.Enrollment {
			code = refusal.EnrollmentSignatureInvalid
		}
		if err := Verify(k, message, valid, domain); err != nil {
			t.Fatal(err)
		}
		for _, b := range [][]byte{valid[:63], noncanonical, identityR, smallR, negativeZeroR, badR, mixedR, identityEquation, corrupt} {
			if err := Verify(k, message, b, domain); !refusal.Is(err, code) {
				t.Fatalf("%x: %v", b, err)
			}
		}
		if err := Verify(k, []byte("altered"), valid, domain); !refusal.Is(err, code) {
			t.Fatal(err)
		}
	}
}

// P-256 range precedes low-S, which precedes equation; raw signatures never invoke DER detection.
func TestP256RangesAndLowS(t *testing.T) {
	c := elliptic.P256()
	n := c.Params().N
	// Fixed public test seeds derive the private scalar and nonce; neither is production key material.
	dSeed := sha256.Sum256([]byte("public P-256 test private seed"))
	kSeed := sha256.Sum256([]byte("public P-256 test nonce seed"))
	scalar := func(b []byte) *big.Int {
		return new(big.Int).Add(new(big.Int).Mod(new(big.Int).SetBytes(b), new(big.Int).Sub(n, big.NewInt(1))), big.NewInt(1))
	}
	d := scalar(dSeed[:])
	nonce := scalar(kSeed[:])
	x, y := c.ScalarBaseMult(d.Bytes())
	k := key(t, "p256:", elliptic.MarshalCompressed(c, x, y))
	message := []byte("public test message")
	digest := sha256.Sum256(message)
	rx, _ := c.ScalarBaseMult(nonce.Bytes())
	r := new(big.Int).Mod(rx, n)
	s := new(big.Int).Mul(r, d)
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(nonce, n))
	s.Mod(s, n)
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	raw := func(r, s *big.Int) []byte {
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	valid := raw(r, s)
	if err := Verify(k, message, valid, envelope.Registration); err != nil {
		t.Fatal(err)
	}
	high := new(big.Int).Sub(n, s)
	cases := []struct {
		name  string
		bytes []byte
		code  refusal.Code
	}{
		{"zero r", raw(big.NewInt(0), high), refusal.RegistrationSignatureInvalid},
		{"r equals n", raw(n, high), refusal.RegistrationSignatureInvalid},
		{"zero s", raw(r, big.NewInt(0)), refusal.RegistrationSignatureInvalid},
		{"s equals n", raw(r, n), refusal.RegistrationSignatureInvalid},
		{"high S", raw(r, high), refusal.SignatureHighS},
		{"high S bad equation", raw(big.NewInt(1), high), refusal.SignatureHighS},
		{"wrong equation", raw(big.NewInt(1), big.NewInt(1)), refusal.RegistrationSignatureInvalid},
		{"half plus one", raw(r, new(big.Int).Add(half, big.NewInt(1))), refusal.SignatureHighS},
		{"half", raw(r, half), refusal.RegistrationSignatureInvalid},
		{"short", valid[:63], refusal.RegistrationSignatureInvalid},
		{"DER", []byte{0x30, 6, 2, 1, 1, 2, 1, 1}, refusal.RegistrationSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(k, message, tc.bytes, envelope.Registration); !refusal.Is(err, tc.code) {
				t.Fatal(err)
			}
		})
	}
	// DER-shaped bytes still denote in-range low raw scalars; equation failure is the expected raw verdict.
	derShaped := make([]byte, 64)
	copy(derShaped, []byte{0x30, 62, 2, 29})
	derShaped[33] = 2
	derShaped[34] = 29
	if err := Verify(k, message, derShaped, envelope.Registration); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
		t.Fatal(err)
	}
	badKey := key(t, "p256:", make([]byte, 32))
	if err := Verify(badKey, message, raw(r, high), envelope.Registration); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
		t.Fatal(err)
	}
}

// A 64-byte DER-shaped signature must pass when its raw scalars verify; no encoding auto-detection may veto it.
func TestP256DERShapedRawPositive(t *testing.T) {
	c := elliptic.P256()
	n := c.Params().N
	message := []byte("public DER-shaped raw test seed")
	seed := sha256.Sum256(message)
	raw := make([]byte, 64)
	copy(raw, []byte{0x30, 62, 2, 29})
	copy(raw[4:32], seed[:28])
	raw[4] = 1
	raw[32] = 1
	raw[33] = 2
	raw[34] = 29
	copy(raw[35:], seed[:29])
	raw[35] = 1
	// Select an on-curve x with a bounded seed-derived search; both DER INTEGERs stay canonical.
	var rx, ry *big.Int
	for i := 0; i < 256; i++ {
		raw[31] = byte(i)
		compressed := append([]byte{2}, raw[:32]...)
		rx, ry = elliptic.UnmarshalCompressed(c, compressed)
		if rx != nil {
			break
		}
	}
	if rx == nil {
		t.Fatal("seed-derived point search exhausted")
	}
	r, s := new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])
	inverse := new(big.Int).ModInverse(r, n)
	digest := sha256.Sum256(message)
	z := new(big.Int).SetBytes(digest[:])
	// Rearrange sR=zG+rQ to derive the public control key Q, without a private key.
	a := new(big.Int).Mod(new(big.Int).Mul(s, inverse), n)
	b := new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(z, inverse)), n)
	ax, ay := c.ScalarMult(rx, ry, a.Bytes())
	bx, by := c.ScalarBaseMult(b.Bytes())
	qx, qy := c.Add(ax, ay, bx, by)
	k := key(t, "p256:", elliptic.MarshalCompressed(c, qx, qy))
	if err := Verify(k, message, raw, envelope.Registration); err != nil {
		t.Fatal(err)
	}
	altered := append(bytes.Clone(message), '!')
	if err := Verify(k, altered, raw, envelope.Registration); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
		t.Fatal(err)
	}
}
