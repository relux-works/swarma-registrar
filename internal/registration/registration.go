// Package registration implements the stateless registration/1 validation stages.
package registration

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/sig"
)

// Body is a schema-checked, ID-checked and cryptographically verified proof.
// It is not enrollment authority or an admission decision. IssuedAt/ExpiresAt
// are Unix seconds; no clock, enrollment, authorization or replay check ran.
type Body struct {
	ID        string
	Key       *keys.Key
	Name      string
	Audience  string
	Nonce     []byte
	IssuedAt  int64
	ExpiresAt int64
}

func Parse(raw []byte) (*Body, error) { return Read(bytes.NewReader(raw)) }
func Read(reader io.Reader) (*Body, error) {
	e, err := envelope.Read(reader, envelope.Registration)
	if err != nil {
		return nil, err
	}
	body, err := parseBody(e.Body)
	if err != nil {
		return nil, err
	}
	if err = e.CheckID(); err != nil {
		return nil, err
	}
	if err = sig.Verify(body.Key, e.Preimage, e.Signature, envelope.Registration); err != nil {
		return nil, err
	}
	body.ID = e.ID
	return body, nil
}
func parseBody(obj map[string]any) (*Body, error) {
	malformed := func() (*Body, error) { return nil, refusal.New(refusal.RegistrationMalformed) }
	fields := []string{"type", "key", "name", "aud", "nonce", "iat", "exp"}
	if len(obj) != len(fields) {
		return malformed()
	}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		s, ok := obj[field].(string)
		if !ok {
			return malformed()
		}
		values[field] = s
	}
	if values["type"] != "registration/1" || len(values["name"]) > 255 || len(values["aud"]) < 1 || len(values["aud"]) > 255 || !ascii(values["aud"]) {
		return malformed()
	}
	key, err := keys.Parse(values["key"], refusal.RegistrationMalformed)
	if err != nil {
		return nil, err
	}
	nonce, ok := envelope.DecodeBase64URL(values["nonce"])
	if !ok || len(nonce) != 16 {
		return malformed()
	}
	iat, iatOK := timestamp(values["iat"])
	exp, expOK := timestamp(values["exp"])
	if !iatOK || !expOK || exp <= iat || exp-iat > 120 {
		return malformed()
	}
	return &Body{Key: key, Name: values["name"], Audience: values["aud"], Nonce: nonce, IssuedAt: iat, ExpiresAt: exp}, nil
}
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
func timestamp(s string) (int64, bool) {
	const layout = "2006-01-02T15:04:05Z"
	if len(s) != 20 {
		return 0, false
	}
	for i := range s {
		switch i {
		case 4, 7:
			if s[i] != '-' {
				return 0, false
			}
		case 10:
			if s[i] != 'T' {
				return 0, false
			}
		case 13, 16:
			if s[i] != ':' {
				return 0, false
			}
		case 19:
			if s[i] != 'Z' {
				return 0, false
			}
		default:
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
		}
	}
	t, err := time.Parse(layout, s)
	if err != nil || t.Year() < 1970 || t.Year() > 9999 || t.Format(layout) != s {
		return 0, false
	}
	return t.Unix(), true
}

var legacy = regexp.MustCompile(`^[a-z0-9][a-z0-9._=\-]{0,254}$`)
var structured = regexp.MustCompile(`^([a-z0-9-]{1,32})_[a-z0-9][a-z0-9-]{0,31}_[a-z0-9]{1,32}(-[a-z0-9]{1,16})?$`)

// StructuredHost parses namespace ownership, not enrollment permission.
func StructuredHost(name string) (string, bool) {
	if !structured.MatchString(name) {
		return "", false
	}
	return strings.SplitN(name, "_", 2)[0], true
}

// CheckName runs row 12 only. Call it after registry/key/window/revocation checks.
// The configured audience, never the request's audience, determines the byte cap.
func (b *Body) CheckName(configuredAudience string) error {
	if (!structured.MatchString(b.Name) && !legacy.MatchString(b.Name)) || len(b.Name) > 253-len(configuredAudience) {
		return refusal.New(refusal.NameInvalid)
	}
	return nil
}

// CheckAudience runs row 14 only, after enrollment permission (row 13).
func (b *Body) CheckAudience(configuredAudience string) error {
	if b.Audience != configuredAudience {
		return refusal.New(refusal.AudienceMismatch)
	}
	return nil
}
