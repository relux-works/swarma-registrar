package library

import (
	"encoding/base64"
	"time"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	core "github.com/relux-works/swarma-registrar/internal/registration"
)

// RegistrationBody holds copied proof data, not enrollment or admission authority.
// Timestamps retain the specification's exact whole-second UTC spelling.
type RegistrationBody struct {
	Key       string
	Name      string
	Audience  string
	Nonce     []byte
	IssuedAt  string
	ExpiresAt string
}

func registrationObject(b RegistrationBody) map[string]any {
	return map[string]any{"type": "registration/1", "key": b.Key, "name": b.Name, "aud": b.Audience, "nonce": base64.RawURLEncoding.EncodeToString(b.Nonce), "iat": b.IssuedAt, "exp": b.ExpiresAt}
}

// BuildRegistration validates unsigned input and returns canonical signing data.
func BuildRegistration(b RegistrationBody, audience string) ([]byte, []byte, error) {
	obj := registrationObject(b)
	raw, err := ccj.Marshal(obj, refusal.RegistrationMalformed)
	if err != nil {
		return nil, nil, err
	}
	if err = CheckRegistration(raw, audience); err != nil {
		return nil, nil, err
	}
	pre, _, err := envelope.SigningInput(envelope.Registration, obj)
	if err != nil {
		return nil, nil, err
	}
	return raw, pre, nil
}

// CheckRegistration checks row 5 and name syntax/cap without enrollment authority.
func CheckRegistration(raw []byte, audience string) error {
	b, err := core.ParseBody(raw)
	if err != nil {
		return err
	}
	return b.CheckName(audience)
}

// AssembleRegistration canonicalizes a schema body and encodes the caller's raw
// signature. It neither verifies nor normalizes that signature.
func AssembleRegistration(raw, signature []byte) ([]byte, error) {
	if _, err := core.ParseBody(raw); err != nil {
		return nil, err
	}
	if len(signature) != 64 {
		return nil, refusal.New(refusal.RegistrationMalformed)
	}
	// ParseBody already established an object and its schema; use the same parser.
	value, err := ccj.Parse(raw, refusal.RegistrationMalformed)
	if err != nil {
		return nil, err
	}
	obj := value.(map[string]any)
	_, id, err := envelope.SigningInput(envelope.Registration, obj)
	if err != nil {
		return nil, err
	}
	return ccj.Marshal(map[string]any{"body": obj, "id": id, "sig": base64.RawURLEncoding.EncodeToString(signature)}, refusal.RegistrationMalformed)
}

// VerifyRegistration preserves the existing registrar's rows 5–7 exactly.
func VerifyRegistration(raw []byte) (*RegistrationBody, error) {
	b, err := core.Parse(raw)
	if err != nil {
		return nil, err
	}
	const layout = "2006-01-02T15:04:05Z"
	return &RegistrationBody{Key: b.Key.Encoding(), Name: b.Name, Audience: b.Audience, Nonce: append([]byte(nil), b.Nonce...), IssuedAt: time.Unix(b.IssuedAt, 0).UTC().Format(layout), ExpiresAt: time.Unix(b.ExpiresAt, 0).UTC().Format(layout)}, nil
}
