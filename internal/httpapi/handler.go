// Package httpapi implements spec §6 routing and checks 1–7 in front of the
// admission core. It supplies a net/http Handler, not a listener or TLS policy.
// Deployment owns HTTPS, ingress limits and transport read/write deadlines.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
)

const registrationPath = "/v1/registration"
const endpointNotFound refusal.Code = "endpoint_not_found"
const methodNotAllowed refusal.Code = "method_not_allowed"
const unsupportedMediaType refusal.Code = "unsupported_media_type"

// Handler is constructed with New and mounted directly so a mux does not replace its routing,
// method or safe-response contract. Its admission dependency is process-owned.
type Handler struct{ core *admission.Admitter }

func New(core *admission.Admitter) (*Handler, error) {
	if core == nil {
		return nil, errors.New("HTTP admission dependency required")
	}
	return &Handler{core: core}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != registrationPath {
		h.refuse(w, r, endpointNotFound, 0)
		return
	}
	if r.Method != http.MethodPost {
		h.refuse(w, r, methodNotAllowed, 0)
		return
	}
	// Limit the actual stream before media checks or parsing. Never trust a
	// declared length, read past cap+1, or let a read error conceal an oversize.
	var body io.Reader = http.NoBody
	if r.Body != nil {
		body = r.Body
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, envelope.MaxBytes+1))
	observed := uint64(len(raw))
	if len(raw) > envelope.MaxBytes {
		h.refuse(w, r, refusal.RequestTooLarge, observed)
		return
	}
	if !supportedMedia(r.Header) {
		h.refuse(w, r, unsupportedMediaType, observed)
		return
	}
	if readErr != nil {
		h.refuse(w, r, refusal.RegistrationMalformed, observed)
		return
	}
	proof, err := registration.Parse(raw)
	if err != nil {
		var typed *refusal.Error
		code := refusal.ServiceUnavailable
		if errors.As(err, &typed) {
			code = typed.Code
		}
		h.refuse(w, r, code, observed)
		return
	}
	token, err := h.core.Admit(r.Context(), admission.Request{Proof: proof, Bytes: observed})
	if err != nil {
		writeRefusal(w, err)
		return
	}
	encoded, _ := json.Marshal(struct {
		JWT string `json:"jwt"`
	}{token})
	w.WriteHeader(http.StatusOK)
	// A delivery failure cannot refund the consumed nonce or retry its JWT.
	_, _ = w.Write(encoded)
}

func supportedMedia(header http.Header) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	// Surrounding whitespace and quoted charset values remain unspecified.
	// Currently media/parameter-name whitespace is trimmed, MIME parameter
	// spacing is permitted and quoted utf-8 is accepted. Tests deliberately
	// do not assert these implementation choices. At most one parameter is
	// allowed, so duplicate parameters cannot be collapsed into one by the parser.
	if strings.Count(values[0], ";") > 1 {
		return false
	}
	// Check the raw name before MIME normalization: RFC 2231 continuations
	// and undecodable extended values can disappear from the returned map.
	if _, parameter, present := strings.Cut(values[0], ";"); present {
		name, _, assigned := strings.Cut(parameter, "=")
		if !assigned || !strings.EqualFold(strings.TrimSpace(name), "charset") {
			return false
		}
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(media, "application/json") || len(params) > 1 {
		return false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	encodings := header.Values("Content-Encoding")
	return len(encodings) == 0 || len(encodings) == 1 && strings.EqualFold(strings.Trim(encodings[0], " \t"), "identity")
}

func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, code refusal.Code, observed uint64) {
	// Refuse deliberately accepts no identity data. Every early verdict follows
	// the same local-durable audit path and honors its terminal failure override.
	writeRefusal(w, h.core.Refuse(r.Context(), code, observed))
}

func status(code refusal.Code) int {
	switch code {
	case endpointNotFound:
		return http.StatusNotFound
	case methodNotAllowed:
		return http.StatusMethodNotAllowed
	case refusal.RequestTooLarge:
		return http.StatusRequestEntityTooLarge
	case unsupportedMediaType:
		return http.StatusUnsupportedMediaType
	case refusal.RegistrationMalformed, refusal.RegistrationIDMismatch, refusal.NameInvalid, refusal.ClockSkew:
		return http.StatusBadRequest
	case refusal.RegistrationSignatureInvalid, refusal.SignatureHighS, refusal.KeyNotEnrolled, refusal.KeyNotValidNow, refusal.HostRevoked, refusal.NameNotPermitted, refusal.AudienceMismatch, refusal.RequestNotYetValid, refusal.RequestExpired:
		return http.StatusForbidden
	case refusal.NonceReplayed:
		return http.StatusConflict
	case refusal.RateLimited:
		return http.StatusTooManyRequests
	case refusal.RegistryUnavailable, refusal.ServiceUnavailable, refusal.AuditUnavailable:
		return http.StatusServiceUnavailable
	}
	return 0
}
func writeRefusal(w http.ResponseWriter, err error) {
	code := refusal.ServiceUnavailable
	var typed *refusal.Error
	if errors.As(err, &typed) && status(typed.Code) != 0 {
		code = typed.Code
	}
	if code == methodNotAllowed {
		w.Header().Set("Allow", "POST")
	}
	var attempt *admission.Error
	if code == refusal.RateLimited && errors.As(err, &attempt) && attempt.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(attempt.RetryAfter, 10))
	}
	encoded, _ := json.Marshal(struct {
		Code    refusal.Code      `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	}{code, "Registration request refused.", map[string]string{}})
	w.WriteHeader(status(code))
	_, _ = w.Write(encoded)
}
