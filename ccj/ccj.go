package ccj

import (
	core "github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Code is a stable specification refusal code.
type Code = refusal.Code

// Error carries only a stable Code; use errors.As to inspect failures.
type Error = refusal.Error

// Schema codes select the refusal associated with the caller's format.
const (
	EnrollmentMalformed   = refusal.EnrollmentMalformed
	RegistrationMalformed = refusal.RegistrationMalformed
)

// Parse refuses duplicate members, lossy numbers and invalid UTF-8. Numbers are
// int64, objects map[string]any and arrays []any. malformed selects the format code.
func Parse(data []byte, malformed Code) (any, error) { return core.Parse(data, malformed) }

// Marshal canonicalizes exactly the value types returned by Parse under CCJ-1.
func Marshal(v any, malformed Code) ([]byte, error) { return core.Marshal(v, malformed) }
