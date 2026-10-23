package registration_test

import (
	"github.com/relux-works/swarma-registrar/internal/apicheck"
	"testing"
)

// The inventory detects added/removed exported names, fields and methods; it
// does not establish semantic compatibility or the presence of external review.
func TestAPISurface(t *testing.T) { apicheck.Check(t) }
