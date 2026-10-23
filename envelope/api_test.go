package envelope_test

import (
	"github.com/relux-works/swarma-registrar/internal/apicheck"
	"testing"
)

// The checked-in list must match exported identifiers, including aliased methods and fields.
// It does not detect semantic changes or prove that a change received review.
func TestAPISurface(t *testing.T) { apicheck.Check(t) }
