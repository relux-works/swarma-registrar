package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func wire(domain Domain) []byte {
	body := `{"sig":"nested","type":"registration/1"}`
	sum := sha256.Sum256([]byte(string(domain) + "\n" + body))
	return []byte(`{"body":` + body + `,"id":"sha256:` + hex.EncodeToString(sum[:]) + `","sig":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `"}`)
}

// Shape and encoding errors refuse before digest comparison; nested sig remains in the preimage.
func TestEnvelopeShapeAndID(t *testing.T) {
	good := wire(Registration)
	e, err := Read(bytes.NewReader(good), Registration)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.CheckID(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(e.Preimage, []byte(`"sig":"nested"`)) || bytes.HasSuffix(e.Preimage, []byte("\n")) {
		t.Fatal("wrong preimage")
	}
	bad := []string{strings.Replace(string(good), `"body":`, `"extra":0,"body":`, 1), strings.Replace(string(good), `{"sig":"nested","type":"registration/1"}`, `[]`, 1), strings.Replace(string(good), `sha256:`, `SHA256:`, 1), strings.Replace(string(good), `"sig":"AAAA`, `"sig":"+AAA`, 1), strings.Replace(string(good), `AA"}`, `AB"}`, 1), strings.Replace(string(good), `AA"}`, `AA="}`, 1), strings.Replace(string(good), `AA"}`, `A"}`, 1)}
	for _, s := range bad {
		if _, err := Parse([]byte(s), Registration); !refusal.Is(err, refusal.RegistrationMalformed) {
			t.Fatalf("%s: %v", s, err)
		}
	}
	e, err = Parse(wire(Enrollment), Registration)
	if err != nil {
		t.Fatal(err)
	}
	if !refusal.Is(e.CheckID(), refusal.RegistrationIDMismatch) {
		t.Fatal("domain separation")
	}
	e, err = Parse(wire(Registration), Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if !refusal.Is(e.CheckID(), refusal.EnrollmentIDMismatch) {
		t.Fatal("enrollment domain separation")
	}
}

// Readers enforce the received-byte limit with absent lengths and stop after one excess byte.
func TestEnvelopeStreamingLimit(t *testing.T) {
	for _, domain := range []Domain{Registration, Enrollment} {
		good := wire(domain)
		padded := append(good, bytes.Repeat([]byte(" "), MaxBytes-len(good))...)
		if _, err := Read(bytes.NewReader(padded), domain); err != nil {
			t.Fatal(err)
		}
		code := refusal.RequestTooLarge
		if domain == Enrollment {
			code = refusal.EnrollmentMalformed
		}
		r := bytes.NewReader(append(padded, []byte("extra")...))
		if _, err := Read(r, domain); !refusal.Is(err, code) {
			t.Fatal(err)
		}
		if r.Len() != 4 {
			t.Fatal("reader overconsumed")
		}
	}
}

// Every required envelope member and type is enforced in both domains, before ID or signature semantics.
func TestEnvelopeRequiredFields(t *testing.T) {
	for _, domain := range []Domain{Registration, Enrollment} {
		good := string(wire(domain))
		parsed, err := Parse([]byte(good), domain)
		if err != nil {
			t.Fatal(err)
		}
		cases := []string{`null`, `[]`, `{}`, `{"body":{},"id":"x","extra":0}`, strings.Replace(good, `"body":`, `"BODY":`, 1), strings.Replace(good, `"id":`, `"ID":`, 1), strings.Replace(good, `"sig":"AAAA`, `"SIG":"AAAA`, 1), strings.Replace(good, `{"sig":"nested","type":"registration/1"}`, `null`, 1), strings.Replace(good, `"`+parsed.ID+`"`, `false`, 1), strings.Replace(good, `"`+base64.RawURLEncoding.EncodeToString(make([]byte, 64))+`"`, `null`, 1)}
		for _, s := range cases {
			if _, err := Parse([]byte(s), domain); !refusal.Is(err, domain.Malformed()) {
				t.Fatalf("%s: %v", s, err)
			}
		}
	}
}
