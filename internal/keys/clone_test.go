package keys

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Clone preserves valid key values and nil, but isolates both object identity
// and raw bytes in both directions; the shallow-raw control targets this test.
func TestKeyCloneRawCopyIsolation(t *testing.T) {
	// RFC 8032 section 7.1 vector 1 public point; RFC 6979 A.2.5 test scalar.
	ed, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	if err != nil {
		t.Fatal(err)
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(scalar)
	for _, tc := range []struct {
		name, prefix string
		raw          []byte
	}{{"ed25519", "ed25519:", ed}, {"p256", "p256:", elliptic.MarshalCompressed(curve, x, y)}} {
		t.Run(tc.name, func(t *testing.T) {
			original, err := ParseEnrollment(tc.prefix + base64.RawURLEncoding.EncodeToString(tc.raw))
			if err != nil {
				t.Fatal("valid source control", err)
			}
			clone := original.Clone()
			if clone == original || clone.Algorithm() != original.Algorithm() || clone.Encoding() != original.Encoding() || !bytes.Equal(clone.Bytes(), original.Bytes()) {
				t.Fatal("clone did not preserve an independent key value")
			}
			if _, err := clone.PublicKey(); err != nil {
				t.Fatal("valid clone control", err)
			}
			before := original.Bytes()
			clone.raw[0] ^= 0xff
			if !bytes.Equal(original.Bytes(), before) {
				t.Fatal("Key.Clone shares raw bytes with its source")
			}
			cloneBefore := clone.Bytes()
			original.raw[len(original.raw)-1] ^= 0xff
			if !bytes.Equal(clone.Bytes(), cloneBefore) {
				t.Fatal("source mutation changed cloned raw bytes")
			}
		})
	}
	var missing *Key
	if missing.Clone() != nil {
		t.Fatal("nil key clone must remain nil")
	}
}
