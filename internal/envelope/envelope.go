// Package envelope parses bounded signed envelopes and constructs their domain-separated input.
package envelope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

const MaxBytes = 65536

type Domain string

const (
	Registration Domain = "swarma-registrar registration/1"
	Enrollment   Domain = "swarma-registrar enrollment/1"
)

func (d Domain) Malformed() refusal.Code {
	if d == Enrollment {
		return refusal.EnrollmentMalformed
	}
	return refusal.RegistrationMalformed
}
func (d Domain) SignatureInvalid() refusal.Code {
	if d == Enrollment {
		return refusal.EnrollmentSignatureInvalid
	}
	return refusal.RegistrationSignatureInvalid
}
func (d Domain) valid() bool { return d == Registration || d == Enrollment }

type Envelope struct {
	Body          map[string]any
	ID            string
	Signature     []byte
	CanonicalBody []byte
	Preimage      []byte
	domain        Domain
	computedID    string
}

// DecodeBase64URL accepts only unpadded URL alphabet and zero unused bits.
func DecodeBase64URL(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && base64.RawURLEncoding.EncodeToString(b) == s
}

// Read bounds the stream before JSON interpretation, without trusting content lengths.
func Read(r io.Reader, d Domain) (*Envelope, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if len(b) > MaxBytes {
		return nil, oversize(d)
	}
	if err != nil {
		return nil, refusal.New(d.Malformed())
	}
	return Parse(b, d)
}
func oversize(d Domain) error {
	if d == Enrollment {
		return refusal.New(refusal.EnrollmentMalformed)
	}
	return refusal.New(refusal.RequestTooLarge)
}

// Parse checks only the envelope shape. Call body schema validation before CheckID.
func Parse(b []byte, d Domain) (*Envelope, error) {
	if len(b) > MaxBytes {
		return nil, oversize(d)
	}
	if !d.valid() {
		return nil, refusal.New(d.Malformed())
	}
	v, err := ccj.Parse(b, d.Malformed())
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok || len(obj) != 3 {
		return nil, refusal.New(d.Malformed())
	}
	body, bodyOK := obj["body"].(map[string]any)
	id, idOK := obj["id"].(string)
	signature, sigOK := obj["sig"].(string)
	if !bodyOK || !idOK || !sigOK || !validID(id) || len(signature) != 86 {
		return nil, refusal.New(d.Malformed())
	}
	sigBytes, ok := DecodeBase64URL(signature)
	if !ok || len(sigBytes) != 64 {
		return nil, refusal.New(d.Malformed())
	}
	canonical, err := ccj.Marshal(body, d.Malformed())
	if err != nil {
		return nil, err
	}
	preimage, digest := signingInput(d, canonical)
	return &Envelope{Body: body, ID: id, Signature: sigBytes, CanonicalBody: canonical, Preimage: preimage, domain: d, computedID: digest}, nil
}
func validID(id string) bool {
	if len(id) != 71 || !strings.HasPrefix(id, "sha256:") {
		return false
	}
	for _, b := range []byte(id[7:]) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func (e *Envelope) CheckID() error {
	if e.ID != e.computedID {
		code := refusal.RegistrationIDMismatch
		if e.domain == Enrollment {
			code = refusal.EnrollmentIDMismatch
		}
		return refusal.New(code)
	}
	return nil
}

// SigningInput canonicalizes only body, retaining any nested member named sig.
func SigningInput(d Domain, body map[string]any) ([]byte, string, error) {
	if !d.valid() {
		return nil, "", refusal.New(d.Malformed())
	}
	canonical, err := ccj.Marshal(body, d.Malformed())
	if err != nil {
		return nil, "", err
	}
	preimage, id := signingInput(d, canonical)
	return preimage, id, nil
}
func signingInput(d Domain, canonical []byte) ([]byte, string) {
	pre := append([]byte(string(d)+"\n"), canonical...)
	hash := sha256.Sum256(pre)
	return pre, "sha256:" + hex.EncodeToString(hash[:])
}
