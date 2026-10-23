package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func encode(prefix string, b []byte) string { return prefix + base64.RawURLEncoding.EncodeToString(b) }
func little(n *big.Int) []byte {
	b := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// Lexemes fail at schema time; recognized lengths and points are deferred to cryptographic validation.
func TestKeyLexemesAndPointChecks(t *testing.T) {
	for _, text := range []string{"unknown:AA", "ed25519:A", "ed25519:AB", "p256:AA=", "ed25519:+A", "ed25519:/A", "ed25519:A A", "ed25519:é", "ed25519:" + string(bytes.Repeat([]byte("A"), 129))} {
		if _, err := Parse(text, refusal.RegistrationMalformed); !refusal.Is(err, refusal.RegistrationMalformed) {
			t.Fatalf("%q: %v", text, err)
		}
	}
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)).Public().(ed25519.PublicKey)
	curve := elliptic.P256()
	goodP := elliptic.MarshalCompressed(curve, curve.Params().Gx, curve.Params().Gy)
	for _, text := range []string{encode("ed25519:", pub), encode("p256:", goodP)} {
		k, err := Parse(text, refusal.RegistrationMalformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.PublicKey(); err != nil {
			t.Fatal(err)
		}
	}
	// p=2^255-19 is the Edwards field prime; y=1 is identity, y=-1 order two, y=0 order four.
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	identity := little(big.NewInt(1))
	negativeZero := bytes.Clone(identity)
	negativeZero[31] |= 128
	// Adding (0,-1) to the standard generator (y=4/5, sign=0) gives (-x,-y), a mixed-order point.
	y := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), p))
	y.Mod(y, p)
	mixed := little(new(big.Int).Sub(p, y))
	mixed[31] |= 128
	// y=2 has no Edwards x square in this field; decompression must reject it.
	badEd := [][]byte{{}, make([]byte, 31), identity, negativeZero, little(big.NewInt(0)), little(big.NewInt(2)), little(new(big.Int).Sub(p, big.NewInt(1))), little(p), little(new(big.Int).Add(p, big.NewInt(1))), mixed}
	for _, b := range badEd {
		k, err := Parse(encode("ed25519:", b), refusal.RegistrationMalformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.PublicKey(); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
			t.Fatalf("ed point %x: %v", b, err)
		}
		if ValidEd25519Point(b) {
			t.Fatalf("accepted %x", b)
		}
	}
	// x=p is out of range; x=1 yields a nonsquare curve RHS; SEC1 identity and uncompressed forms are forbidden.
	outOfRange := append([]byte{2}, curve.Params().P.FillBytes(make([]byte, 32))...)
	offCurve := append([]byte{2}, make([]byte, 32)...)
	offCurve[32] = 1
	for _, b := range [][]byte{{0}, pub, elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy), append([]byte{4}, goodP[1:]...), outOfRange, offCurve} {
		k, err := Parse(encode("p256:", b), refusal.RegistrationMalformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = k.PublicKey(); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
			t.Fatalf("p point %x: %v", b, err)
		}
	}
}

// Enrollment treats recognized bad points as malformed data, alongside valid controls of both algorithms.
func TestEnrollmentKeys(t *testing.T) {
	c := elliptic.P256()
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)).Public().(ed25519.PublicKey)
	for _, text := range []string{encode("ed25519:", pub), encode("p256:", elliptic.MarshalCompressed(c, c.Params().Gx, c.Params().Gy))} {
		if _, err := ParseEnrollment(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"rsa:AA", "ed25519:AB", encode("ed25519:", make([]byte, 32)), encode("p256:", pub)} {
		if _, err := ParseEnrollment(text); !refusal.Is(err, refusal.EnrollmentMalformed) {
			t.Fatal(err)
		}
	}
}

// A family of independently seeded valid public points and both generator signs guards against over-rejection.
func TestEd25519PositiveFamily(t *testing.T) {
	for i := byte(0); i < 16; i++ {
		pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32)).Public().(ed25519.PublicKey)
		if !ValidEd25519Point(pub) {
			t.Fatalf("seed byte %d", i)
		}
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	y := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), p))
	y.Mod(y, p)
	base := little(y)
	if !ValidEd25519Point(base) {
		t.Fatal("generator")
	}
	base[31] |= 128
	if !ValidEd25519Point(base) {
		t.Fatal("negative generator")
	}
}
