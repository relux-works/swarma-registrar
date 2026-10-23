package enrollment

import (
	"github.com/relux-works/swarma-registrar/internal/library"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Policy contains copied deployment pins and host classifications.
type Policy = library.Policy

// Record is a read-only verified enrollment with copying accessors.
type Record = library.Record

// Window contains an exact encoded key and its half-open interval.
type Window = library.Window

// UIDEntry is one verified helper narrowing rule; the caller enforces peer identity.
type UIDEntry = library.UIDEntry

// Code is a stable specification refusal code.
type Code = refusal.Code

// Error exposes typed refusals without input data; use errors.As.
type Error = refusal.Error

// Enrollment and name-check refusal codes.
const (
	EnrollmentMalformed        = refusal.EnrollmentMalformed
	EnrollmentSigsUnsupported  = refusal.EnrollmentSigsUnsupported
	EnrollmentIDMismatch       = refusal.EnrollmentIDMismatch
	EnrollmentSignatureInvalid = refusal.EnrollmentSignatureInvalid
	RegistryUnavailable        = refusal.RegistryUnavailable
	NameInvalid                = refusal.NameInvalid
	NameNotPermitted           = refusal.NameNotPermitted
)

// NewPolicy pins exactly one Ed25519 publisher. The caller supplies a validated
// canonical audience and trusted station/nonstation classification for every host.
func NewPolicy(audience, publisher string, stations map[string]bool) (*Policy, error) {
	return library.NewPolicy(audience, publisher, stations)
}
