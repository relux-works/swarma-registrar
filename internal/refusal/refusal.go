// Package refusal defines stable wire refusal codes without request data.
package refusal

import "errors"

type Code string

const (
	RegistrationMalformed        Code = "registration_malformed"
	EnrollmentMalformed          Code = "enrollment_malformed"
	RequestTooLarge              Code = "request_too_large"
	RegistrationIDMismatch       Code = "registration_id_mismatch"
	EnrollmentIDMismatch         Code = "enrollment_id_mismatch"
	RegistrationSignatureInvalid Code = "registration_signature_invalid"
	EnrollmentSignatureInvalid   Code = "enrollment_signature_invalid"
	SignatureHighS               Code = "signature_high_s"
	NameInvalid                  Code = "name_invalid"
	AudienceMismatch             Code = "audience_mismatch"
)

// Error carries only a stable code, never a raw input or implementation diagnostic.
type Error struct{ Code Code }

func (e *Error) Error() string     { return string(e.Code) }
func New(code Code) *Error         { return &Error{Code: code} }
func Is(err error, code Code) bool { var e *Error; return errors.As(err, &e) && e.Code == code }
