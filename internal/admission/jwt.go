package admission

import (
	"encoding/base64"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
)

func jwtInput(p *registration.Body, audience string, now int64) ([]byte, string, error) {
	header, err := ccj.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT"}, refusal.ServiceUnavailable)
	if err != nil {
		return nil, "", err
	}
	payload, err := ccj.Marshal(map[string]any{"iss": "swarma-registrar", "aud": []any{audience}, "sub": p.Name, "iat": now, "nbf": now, "exp": now + 120, "jti": p.ID}, refusal.ServiceUnavailable)
	if err != nil {
		return nil, "", err
	}
	prefix := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return []byte(prefix), prefix, nil
}
