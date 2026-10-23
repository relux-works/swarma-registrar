package registration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func fixture() map[string]any {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	return map[string]any{"type": "registration/1", "key": "ed25519:" + base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), "name": "host-a_project_dev", "aud": "example.org", "nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x17}, 16)), "iat": "2024-02-29T12:00:00Z", "exp": "2024-02-29T12:02:00Z"}
}
func signed(t *testing.T, b map[string]any, domain envelope.Domain) []byte {
	t.Helper()
	pre, id, err := envelope.SigningInput(domain, b)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
	raw, err := ccj.Marshal(map[string]any{"body": b, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, pre))}, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Body lexemes, schema and durations fail before IDs and cryptography; valid boundaries remain accepted.
func TestBodySchema(t *testing.T) {
	cases := []struct {
		name, field string
		value       any
		remove      bool
	}{
		{"missing type", "type", nil, true}, {"unknown", "extra", "x", false}, {"wrong type", "type", "enrollment/1", false},
		{"key type", "key", int64(1), false}, {"key prefix", "key", "rsa:AA", false}, {"key base64", "key", "ed25519:AB", false}, {"key ASCII", "key", "ed25519:é", false}, {"key length", "key", strings.Repeat("a", 129), false},
		{"name type", "name", nil, false}, {"name wire cap", "name", strings.Repeat("a", 256), false},
		{"aud empty", "aud", "", false}, {"aud ASCII", "aud", "é", false}, {"aud cap", "aud", strings.Repeat("a", 256), false}, {"aud type", "aud", false, false},
		{"nonce type", "nonce", int64(1), false}, {"nonce length", "nonce", "AA", false}, {"nonce trailing bits", "nonce", strings.Repeat("A", 21) + "B", false}, {"nonce pad", "nonce", strings.Repeat("A", 22) + "==", false},
		{"iat type", "iat", int64(1), false}, {"exp type", "exp", nil, false}, {"bad leap", "iat", "2023-02-29T12:00:00Z", false}, {"leap second", "iat", "2024-02-29T12:00:60Z", false}, {"offset", "iat", "2024-02-29T12:00:00+00:00", false}, {"lower t", "iat", "2024-02-29t12:00:00Z", false}, {"fraction", "iat", "2024-02-29T12:00:00.1Z", false}, {"before epoch", "iat", "1969-12-31T23:59:59Z", false}, {"non padded", "iat", "2024-2-29T12:00:00Z", false},
		{"duration zero", "exp", "2024-02-29T12:00:00Z", false}, {"duration negative", "exp", "2024-02-29T11:59:59Z", false}, {"duration 121", "exp", "2024-02-29T12:02:01Z", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := fixture()
			if tc.remove {
				delete(b, tc.field)
			} else {
				b[tc.field] = tc.value
			}
			if _, err := Parse(signed(t, b, envelope.Registration)); !refusal.Is(err, refusal.RegistrationMalformed) {
				t.Fatal(err)
			}
		})
	}
	for _, field := range []string{"type", "key", "name", "aud", "nonce", "iat", "exp"} {
		b := fixture()
		delete(b, field)
		if _, err := Parse(signed(t, b, envelope.Registration)); !refusal.Is(err, refusal.RegistrationMalformed) {
			t.Fatal(err)
		}
	}
	for _, times := range [][2]string{{"1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"}, {"2024-02-29T12:00:00Z", "2024-02-29T12:02:00Z"}, {"9999-12-31T23:59:58Z", "9999-12-31T23:59:59Z"}} {
		b := fixture()
		b["iat"], b["exp"] = times[0], times[1]
		r, err := Parse(signed(t, b, envelope.Registration))
		if err != nil {
			t.Fatal(err)
		}
		if r.ExpiresAt <= r.IssuedAt || r.Key == nil || len(r.Nonce) != 16 {
			t.Fatal("missing parsed fields")
		}
	}
}

// Precedence is schema, ID, then strict signature; name/audience semantics stay deferred past registry admission.
func TestPrecedenceAndDeferredSemantics(t *testing.T) {
	valid := signed(t, fixture(), envelope.Registration)
	if _, err := Parse(valid); err != nil {
		t.Fatal(err)
	}
	wrongDomain := signed(t, fixture(), envelope.Enrollment)
	if _, err := Parse(wrongDomain); !refusal.Is(err, refusal.RegistrationIDMismatch) {
		t.Fatal(err)
	}
	b := fixture()
	b["key"] = "p256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	raw := signed(t, b, envelope.Registration)
	if _, err := Parse(raw); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"id":"sha256:`), []byte(`"id":"sha256:f`), 1)
	if _, err := Parse(raw); !refusal.Is(err, refusal.RegistrationMalformed) {
		t.Fatal(err)
	}
	b = fixture()
	b["name"] = "INVALID"
	b["aud"] = "other.example.org"
	r, err := Parse(signed(t, b, envelope.Registration))
	if err != nil {
		t.Fatal(err)
	}
	if !refusal.Is(r.CheckName("example.org"), refusal.NameInvalid) {
		t.Fatal("name semantics")
	}
	if !refusal.Is(r.CheckAudience("example.org"), refusal.AudienceMismatch) {
		t.Fatal("audience semantics")
	}
	// A signature from the wrong domain still fails after replacing only its ID with the required-domain digest.
	v, err := ccj.Parse(wrongDomain, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(map[string]any)
	_, id, _ := envelope.SigningInput(envelope.Registration, fixture())
	obj["id"] = id
	raw, err = ccj.Marshal(obj, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); !refusal.Is(err, refusal.RegistrationSignatureInvalid) {
		t.Fatal(err)
	}
	// Legal wire whitespace and escaped aliases preserve the same signed semantic body.
	changed := bytes.Replace(valid, []byte(`"name":`), []byte(`"\u006eame" : `), 1)
	changed = append([]byte(" \n"), changed...)
	if _, err := Parse(changed); err != nil {
		t.Fatal(err)
	}
}

// Names use the legacy syntax union and configured-audience mxid cap; structured ownership parsing is exact.
func TestNames(t *testing.T) {
	for _, name := range []string{"", "Upper", "é", "x:y", "@x", "x/y", "x*", "x y", "=x", strings.Repeat("a", 243)} {
		r := &Body{Name: name}
		if !refusal.Is(r.CheckName("example.org"), refusal.NameInvalid) {
			t.Fatalf("%q", name)
		}
	}
	for _, name := range []string{"legacy.dev", "host-a_project_dev", "host-a_project_dev-q", "a_b_c", strings.Repeat("a", 242), "x__y"} {
		r := &Body{Name: name, Audience: "example.org"}
		if err := r.CheckName("example.org"); err != nil {
			t.Fatal(err)
		}
		if err := r.CheckAudience("example.org"); err != nil {
			t.Fatal(err)
		}
	}
	r := &Body{Name: strings.Repeat("a", 243), Audience: "a"}
	if !refusal.Is(r.CheckName("example.org"), refusal.NameInvalid) {
		t.Fatal("used attacker audience")
	}
	for _, name := range []string{"host-a_project_dev-q", "-_a_b", strings.Repeat("h", 32) + "_" + strings.Repeat("p", 32) + "_" + strings.Repeat("r", 32) + "-" + strings.Repeat("q", 16)} {
		if _, ok := StructuredHost(name); !ok {
			t.Fatalf("%q", name)
		}
	}
	for _, name := range []string{"host_project_dev-q-q", "host__dev", "host_project_Dev", "host_project_dev_foo", "host_project_dev-", strings.Repeat("h", 33) + "_p_r", "host_-project_dev", "host_project_" + strings.Repeat("r", 33), "host_project_dev-" + strings.Repeat("q", 17)} {
		if _, ok := StructuredHost(name); ok {
			t.Fatalf("%q", name)
		}
	}
}

// Every timestamp component is strict; duration is measured across Gregorian day boundaries.
func TestTimestampBoundaries(t *testing.T) {
	bad := []string{"2024-00-01T00:00:00Z", "2024-13-01T00:00:00Z", "2024-04-31T00:00:00Z", "2024-01-00T00:00:00Z", "2024-01-01T24:00:00Z", "2024-01-01T00:60:00Z", "2024-01-01T00:00:60Z", "2024-01-01T00:00:00z", "2024-01-01 00:00:00Z", "2024-01-01T00:00:00.0Z", "1900-02-29T00:00:00Z", "0000-01-01T00:00:00Z"}
	for _, s := range bad {
		if _, ok := timestamp(s); ok {
			t.Fatalf("accepted %s", s)
		}
	}
	for _, s := range []string{"1970-01-01T00:00:00Z", "2000-02-29T00:00:00Z", "2024-12-31T23:59:59Z", "9999-12-31T23:59:59Z"} {
		if _, ok := timestamp(s); !ok {
			t.Fatalf("refused %s", s)
		}
	}
	b := fixture()
	b["iat"] = "2024-02-29T23:59:00Z"
	b["exp"] = "2024-03-01T00:01:00Z"
	if _, err := Parse(signed(t, b, envelope.Registration)); err != nil {
		t.Fatal(err)
	}
	b["exp"] = "2024-03-01T00:01:01Z"
	if _, err := Parse(signed(t, b, envelope.Registration)); !refusal.Is(err, refusal.RegistrationMalformed) {
		t.Fatal(err)
	}
}

// P-256 proofs traverse the complete schema/id/signature pipeline; low-S wins over deferred name defects.
func TestP256RegistrationPipeline(t *testing.T) {
	c := elliptic.P256()
	n := c.Params().N
	seed := sha256.Sum256([]byte("public registration P-256 seed"))
	nonceSeed := sha256.Sum256([]byte("public registration P-256 nonce seed"))
	scalar := func(b []byte) *big.Int {
		return new(big.Int).Add(new(big.Int).Mod(new(big.Int).SetBytes(b), new(big.Int).Sub(n, big.NewInt(1))), big.NewInt(1))
	}
	d, k := scalar(seed[:]), scalar(nonceSeed[:])
	x, y := c.ScalarBaseMult(d.Bytes())
	b := fixture()
	b["key"] = "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(c, x, y))
	b["name"] = "INVALID"
	pre, id, err := envelope.SigningInput(envelope.Registration, b)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pre)
	rx, _ := c.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(rx, n)
	s := new(big.Int).Mul(r, d)
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(k, n))
	s.Mod(s, n)
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(n), 1)) > 0 {
		s.Sub(n, s)
	}
	wire := func(s *big.Int) []byte {
		t.Helper()
		raw := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		out, err := ccj.Marshal(map[string]any{"body": b, "id": id, "sig": base64.RawURLEncoding.EncodeToString(raw)}, refusal.RegistrationMalformed)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	proof, err := Parse(wire(s))
	if err != nil {
		t.Fatal(err)
	}
	if proof.Key.Encoding() != b["key"] {
		t.Fatal("wrong key")
	}
	if !refusal.Is(proof.CheckName("example.org"), refusal.NameInvalid) {
		t.Fatal("deferred name")
	}
	if _, err := Parse(wire(new(big.Int).Sub(n, s))); !refusal.Is(err, refusal.SignatureHighS) {
		t.Fatal(err)
	}
	// A well-formed unequal ID wins over high-S and the invalid name.
	bad := wire(new(big.Int).Sub(n, s))
	last := len(id) - 1
	replacement := byte('0')
	if id[last] == '0' {
		replacement = '1'
	}
	bad = bytes.Replace(bad, []byte(id), append([]byte(id[:last]), replacement), 1)
	if _, err := Parse(bad); !refusal.Is(err, refusal.RegistrationIDMismatch) {
		t.Fatal(err)
	}
}
