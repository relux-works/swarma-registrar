package envelope

import (
	core "github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/sig"
)

// Domain selects the exact domain-separated envelope preimage.
type Domain = core.Domain

// Supported domains do not imply body-schema or registration-proof validation.
const (
	Registration = core.Registration
	Enrollment   = core.Enrollment
)

// Envelope contains parsed bytes and body values. CheckID follows body schema
// validation when used in a larger phased validator. Treat these values as data.
type Envelope = core.Envelope

// Code is a stable specification refusal code.
type Code = refusal.Code

// Error exposes the stable refusal without input data; use errors.As.
type Error = refusal.Error

// Envelope parsing and signature refusal codes, including the P-256 low-S rule.
const (
	RegistrationMalformed        = refusal.RegistrationMalformed
	EnrollmentMalformed          = refusal.EnrollmentMalformed
	RequestTooLarge              = refusal.RequestTooLarge
	RegistrationIDMismatch       = refusal.RegistrationIDMismatch
	EnrollmentIDMismatch         = refusal.EnrollmentIDMismatch
	RegistrationSignatureInvalid = refusal.RegistrationSignatureInvalid
	EnrollmentSignatureInvalid   = refusal.EnrollmentSignatureInvalid
	SignatureHighS               = refusal.SignatureHighS
)

// Parse applies only bounded CCJ-1 and basic envelope shape validation.
func Parse(raw []byte, domain Domain) (*Envelope, error) { return core.Parse(raw, domain) }

// SigningInput returns canonical domain-separated bytes and the body ID.
func SigningInput(domain Domain, body map[string]any) ([]byte, string, error) {
	return core.SigningInput(domain, body)
}

// Verify parses fresh input, checks its ID, and verifies the strict signature
// against the caller's exact key encoding. It does not validate body schema or
// decide key provenance, enrollment publisher policy or registration authority.
// Use enrollment.Policy.Parse or registry.Loader for enrollment authority.
func Verify(raw []byte, domain Domain, publicKey string) (*Envelope, error) {
	e, err := core.Parse(raw, domain)
	if err != nil {
		return nil, err
	}
	if err = e.CheckID(); err != nil {
		return nil, err
	}
	k, err := keys.Parse(publicKey, domain.Malformed())
	if err != nil {
		return nil, err
	}
	if err = sig.Verify(k, e.Preimage, e.Signature, domain); err != nil {
		return nil, err
	}
	return e, nil
}
