package registration

import (
	"github.com/relux-works/swarma-registrar/internal/library"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Body is unsigned input or verified proof data, never an admission decision.
// Key is the exact prefixed public-key encoding. Nonce must contain 16 bytes.
// IssuedAt and ExpiresAt use YYYY-MM-DDTHH:MM:SSZ, not numeric Unix seconds.
// Returned bodies own their nonce bytes; callers may edit them before rebuilding.
type Body = library.RegistrationBody

// Code is a stable specification refusal code.
type Code = refusal.Code

// Error exposes a typed, input-free refusal; use errors.As.
type Error = refusal.Error

// Refusals from unsigned validation and complete-proof verification.
const (
	RegistrationMalformed        = refusal.RegistrationMalformed
	RequestTooLarge              = refusal.RequestTooLarge
	NameInvalid                  = refusal.NameInvalid
	RegistrationIDMismatch       = refusal.RegistrationIDMismatch
	RegistrationSignatureInvalid = refusal.RegistrationSignatureInvalid
	SignatureHighS               = refusal.SignatureHighS
)

// Build checks the body and name against a trusted configured audience, returning
// canonical body bytes and the domain-separated preimage for the caller to sign.
// On refusal both byte slices are nil. No private key is accepted or generated.
func Build(body Body, configuredAudience string) (canonicalBody, preimage []byte, err error) {
	return library.BuildRegistration(body, configuredAudience)
}

// Check validates unsigned CCJ-1 body/schema and §5 name syntax/mxid byte cap.
// The caller supplies a validated configured audience, never the proof's audience.
// It does not compare audiences, validate key points, or establish authority.
func Check(body []byte, configuredAudience string) error {
	return library.CheckRegistration(body, configuredAudience)
}

// Assemble checks body schema, computes its ID and encodes exactly 64 raw
// signature bytes as canonical unpadded base64url. It canonicalizes the body,
// but does not verify or normalize the signature. Call Verify before release.
func Assemble(body, signature []byte) ([]byte, error) {
	return library.AssembleRegistration(body, signature)
}

// Verify applies registrar rows 5–7: schema, ID, selected key and strict signature
// including P-256 low-S. It returns copied body data or nil with a typed refusal.
// Name, enrollment, audience equality, clock and replay policy remain unchecked.
func Verify(proof []byte) (*Body, error) { return library.VerifyRegistration(proof) }
