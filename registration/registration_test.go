package registration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registration"
)

// RFC 8032 section 7.1 test 1 is published test material, never a deployment key.
func testPrivate() ed25519.PrivateKey {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	return ed25519.NewKeyFromSeed(seed)
}
func fields() registration.Body {
	return registration.Body{Key: "ed25519:" + base64.RawURLEncoding.EncodeToString(testPrivate().Public().(ed25519.PublicKey)), Name: "host-a_project_role", Audience: "example.org", Nonce: make([]byte, 16), IssuedAt: "2030-01-01T00:01:40Z", ExpiresAt: "2030-01-01T00:02:00Z"}
}
func refusal(t *testing.T, err error, want registration.Code) {
	t.Helper()
	var typed *registration.Error
	if !errors.As(err, &typed) || typed.Code != want || err.Error() != string(want) {
		t.Fatalf("refusal = %v, want %s", err, want)
	}
}
func build(t *testing.T, f registration.Body) ([]byte, []byte) {
	t.Helper()
	body, pre, err := registration.Build(f, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	return body, pre
}
func assemble(t *testing.T, body, sig []byte) []byte {
	t.Helper()
	proof, err := registration.Assemble(body, sig)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
func object(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}
func encode(t *testing.T, obj any) []byte {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Unsigned checks reject each schema class and both name grammars' forbidden
// neighbors with typed, input-free errors. Valid boundaries remain buildable.
func TestCheckRefusals(t *testing.T) {
	body, _ := build(t, fields())
	tests := []struct {
		name string
		edit func(map[string]any)
		code registration.Code
	}{
		{"unknown", func(m map[string]any) { m["extra"] = "x" }, registration.RegistrationMalformed},
		{"missing", func(m map[string]any) { delete(m, "key") }, registration.RegistrationMalformed},
		{"field-type", func(m map[string]any) { m["iat"] = int64(1) }, registration.RegistrationMalformed},
		{"type", func(m map[string]any) { m["type"] = "enrollment/1" }, registration.RegistrationMalformed},
		{"name-wire-length", func(m map[string]any) { m["name"] = strings.Repeat("a", 256) }, registration.RegistrationMalformed},
		{"aud-empty", func(m map[string]any) { m["aud"] = "" }, registration.RegistrationMalformed},
		{"aud-long", func(m map[string]any) { m["aud"] = strings.Repeat("a", 256) }, registration.RegistrationMalformed},
		{"aud-nonascii", func(m map[string]any) { m["aud"] = "é" }, registration.RegistrationMalformed},
		{"key-prefix", func(m map[string]any) { m["key"] = "rsa:AA" }, registration.RegistrationMalformed},
		{"key-length", func(m map[string]any) { m["key"] = "ed25519:" + strings.Repeat("A", 124) }, registration.RegistrationMalformed},
		{"key-padding", func(m map[string]any) { m["key"] = m["key"].(string) + "=" }, registration.RegistrationMalformed},
		{"nonce-length", func(m map[string]any) { m["nonce"] = "AA" }, registration.RegistrationMalformed},
		{"nonce-padding", func(m map[string]any) { m["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA=" }, registration.RegistrationMalformed},
		{"nonce-unused-bits", func(m map[string]any) { m["nonce"] = "AAAAAAAAAAAAAAAAAAAAAB" }, registration.RegistrationMalformed},
		{"iat-fraction", func(m map[string]any) { m["iat"] = "2030-01-01T00:01:40.0Z" }, registration.RegistrationMalformed},
		{"exp-offset", func(m map[string]any) { m["exp"] = "2030-01-01T00:02:00+00:00" }, registration.RegistrationMalformed},
		{"date", func(m map[string]any) { m["exp"] = "2030-02-30T00:02:00Z" }, registration.RegistrationMalformed},
		{"year", func(m map[string]any) { m["iat"] = "1969-01-01T00:00:00Z" }, registration.RegistrationMalformed},
		{"duration-zero", func(m map[string]any) { m["exp"] = m["iat"] }, registration.RegistrationMalformed},
		{"duration-reversed", func(m map[string]any) { m["exp"] = "2030-01-01T00:01:39Z" }, registration.RegistrationMalformed},
		{"duration-121", func(m map[string]any) { m["exp"] = "2030-01-01T00:03:41Z" }, registration.RegistrationMalformed},
		{"name-grammar", func(m map[string]any) { m["name"] = "Bad/name" }, registration.NameInvalid},
		{"leading-hyphen-legacy", func(m map[string]any) { m["name"] = "-legacy" }, registration.NameInvalid},
		{"configured-cap", func(m map[string]any) { m["name"] = strings.Repeat("a", 243); m["aud"] = "x" }, registration.NameInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := object(t, body)
			tt.edit(m)
			refusal(t, registration.Check(encode(t, m), "example.org"), tt.code)
		})
	}
	for _, raw := range [][]byte{[]byte(`[]`), []byte(`{"key":"a","key":"b"}`), []byte("\xff"), []byte(`{"type":1.0}`)} {
		refusal(t, registration.Check(raw, "example.org"), registration.RegistrationMalformed)
	}
	refusal(t, registration.Check(bytes.Repeat([]byte(" "), 65537), "example.org"), registration.RequestTooLarge)
	for _, name := range []string{"host-a_project_role", "-node_project_role", "legacy.name=1", strings.Repeat("a", 242)} {
		f := fields()
		f.Name = name
		f.ExpiresAt = "2030-01-01T00:03:40Z"
		b, _ := build(t, f)
		if err := registration.Check(b, "example.org"); err != nil {
			t.Fatal(err)
		}
	}
	// Schema-only checks defer point validity and audience equality to later rows.
	f := fields()
	f.Key = "p256:AA"
	f.Audience = "other.example"
	build(t, f)
}

// Build returns no partial signing output on refusal; Assemble requires a schema
// body and exactly 64 raw signature bytes but deliberately leaves crypto to Verify.
func TestBuildAndAssembleRefusals(t *testing.T) {
	for _, tc := range []struct {
		edit func(*registration.Body)
		want registration.Code
	}{
		{func(f *registration.Body) { f.Nonce = make([]byte, 15) }, registration.RegistrationMalformed},
		{func(f *registration.Body) { f.Name = "Invalid" }, registration.NameInvalid},
		{func(f *registration.Body) { f.IssuedAt = "bad" }, registration.RegistrationMalformed},
	} {
		f := fields()
		tc.edit(&f)
		b, p, err := registration.Build(f, "example.org")
		refusal(t, err, tc.want)
		if b != nil || p != nil {
			t.Fatalf("partial build: %q %q %v", b, p, err)
		}
	}
	b, p := build(t, fields())
	for _, n := range []int{0, 63, 65} {
		raw, err := registration.Assemble(b, make([]byte, n))
		refusal(t, err, registration.RegistrationMalformed)
		if raw != nil {
			t.Fatal("partial envelope")
		}
	}
	raw, err := registration.Assemble([]byte(`{}`), make([]byte, 64))
	refusal(t, err, registration.RegistrationMalformed)
	if raw != nil {
		t.Fatal("partial envelope")
	}
	if _, err := registration.Verify(assemble(t, b, ed25519.Sign(testPrivate(), p))); err != nil {
		t.Fatal(err)
	}
}

// Verify preserves rows 5, 6, 7 ordering, algorithm-prefix selection and exact
// signatures, without conflating a verified proof with name/admission authority.
func TestVerifyRefusals(t *testing.T) {
	b, p := build(t, fields())
	signature := ed25519.Sign(testPrivate(), p)
	proof := assemble(t, b, signature)
	cases := []struct {
		name string
		edit func(map[string]any)
		want registration.Code
	}{
		{"body-after-sign", func(m map[string]any) { m["body"].(map[string]any)["name"] = "other" }, registration.RegistrationIDMismatch},
		{"wrong-id", func(m map[string]any) { m["id"] = "sha256:" + strings.Repeat("0", 64) }, registration.RegistrationIDMismatch},
		{"schema-before-id", func(m map[string]any) {
			m["body"].(map[string]any)["type"] = "bad"
			m["id"] = "sha256:" + strings.Repeat("0", 64)
		}, registration.RegistrationMalformed},
		{"sig-padding", func(m map[string]any) { m["sig"] = m["sig"].(string) + "=" }, registration.RegistrationMalformed},
		{"sig-unused-bits", func(m map[string]any) {
			s := m["sig"].(string)
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			i := strings.IndexByte(alphabet, s[len(s)-1])
			m["sig"] = s[:len(s)-1] + string(alphabet[i+1])
		}, registration.RegistrationMalformed},
		{"invalid-equation", func(m map[string]any) {
			s := bytes.Clone(signature)
			s[63] ^= 1
			m["sig"] = base64.RawURLEncoding.EncodeToString(s)
		}, registration.RegistrationSignatureInvalid},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m := object(t, proof)
			tt.edit(m)
			got, err := registration.Verify(encode(t, m))
			refusal(t, err, tt.want)
			if got != nil {
				t.Fatal("partial verified body")
			}
		})
	}
	changed := object(t, b)
	changed["name"] = "other"
	rebound := assemble(t, encode(t, changed), signature)
	_, err := registration.Verify(rebound)
	refusal(t, err, registration.RegistrationSignatureInvalid)
	for _, key := range []string{"p256:" + strings.TrimPrefix(fields().Key, "ed25519:"), "ed25519:AA"} {
		f := fields()
		f.Key = key
		body, pre := build(t, f)
		_, err = registration.Verify(assemble(t, body, ed25519.Sign(testPrivate(), pre)))
		refusal(t, err, registration.RegistrationSignatureInvalid)
	}
	f := fields()
	f.Name = "Invalid"
	m := object(t, b)
	m["name"] = f.Name
	// Assemble and Verify run schema/crypto only, leaving row 12 to Check/admission.
	rawBody := encode(t, m)
	// Obtain the preimage independently by the normative domain concatenation.
	canonical := bytes.Replace(b, []byte(`"host-a_project_role"`), []byte(`"Invalid"`), 1)
	raw := assemble(t, rawBody, ed25519.Sign(testPrivate(), append([]byte("swarma-registrar registration/1\n"), canonical...)))
	if _, err = registration.Verify(raw); err != nil {
		t.Fatal(err)
	}
	refusal(t, registration.Check(rawBody, "example.org"), registration.NameInvalid)
	if _, err = registration.Verify(proof); err != nil {
		t.Fatal(err)
	}
	_, err = registration.Verify(bytes.Repeat([]byte(" "), 65537))
	refusal(t, err, registration.RequestTooLarge)
}

// RFC 6979 Appendix A.2.5 supplies the published test scalar and nonce for
// SHA-256("sample"). This helper uses them as fixed test inputs, independently
// performs ECDSA over our actual preimage, and emits fixed-width low/high S.
func p256(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	c := elliptic.P256()
	n := c.Params().N
	d, ok := new(big.Int).SetString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16)
	if !ok {
		t.Fatal("test scalar")
	}
	k, ok := new(big.Int).SetString("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60", 16)
	if !ok {
		t.Fatal("test nonce")
	}
	x, y := c.ScalarBaseMult(d.Bytes())
	f := fields()
	f.Key = "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(c, x, y))
	body, pre := build(t, f)
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
	low := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	s.Sub(n, s)
	high := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return body, low, high
}

// The high-S twin must be refused; both supported algorithms round-trip all body
// fields with canonical body/preimage/envelope bytes and no caller slice aliasing.
func TestRoundTrips(t *testing.T) {
	b, low, high := p256(t)
	got, err := registration.Verify(assemble(t, b, high))
	refusal(t, err, registration.SignatureHighS)
	if got != nil {
		t.Fatal("high-S body returned")
	}
	// Relabel a compressed P-256 point as Ed25519: never infer the algorithm.
	wrong := object(t, b)
	wrong["key"] = "ed25519:" + strings.TrimPrefix(wrong["key"].(string), "p256:")
	_, err = registration.Verify(assemble(t, encode(t, wrong), low))
	refusal(t, err, registration.RegistrationSignatureInvalid)
	edBody, pre := build(t, fields())
	if !bytes.Equal(pre, append([]byte("swarma-registrar registration/1\n"), edBody...)) {
		t.Fatal("preimage")
	}
	for _, tc := range []struct{ body, sig []byte }{{b, low}, {edBody, ed25519.Sign(testPrivate(), pre)}} {
		raw := assemble(t, tc.body, tc.sig)
		result, err := registration.Verify(raw)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, err := registration.Build(*result, "example.org")
		if err != nil || !bytes.Equal(canonical, tc.body) {
			t.Fatalf("roundtrip: %s %v", canonical, err)
		}
		env := object(t, raw)
		digest := sha256.Sum256(append([]byte("swarma-registrar registration/1\n"), tc.body...))
		if env["id"] != "sha256:"+hex.EncodeToString(digest[:]) || env["sig"] != base64.RawURLEncoding.EncodeToString(tc.sig) {
			t.Fatal("ID/signature encoding")
		}
		if bytes.Equal(tc.body, edBody) && !reflect.DeepEqual(*result, fields()) {
			t.Fatalf("body fields: %+v", result)
		}
		canonicalEnvelope := encode(t, env)
		if !bytes.Equal(raw, canonicalEnvelope) {
			t.Fatal("noncanonical envelope")
		}
		result.Nonce[0] = 255
		again, err := registration.Verify(raw)
		if err != nil || again.Nonce[0] != 0 {
			t.Fatal("aliased body")
		}
	}
}
