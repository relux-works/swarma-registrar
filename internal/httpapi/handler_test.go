package httpapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/envelope"
)

func request(raw []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/registration", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	return r
}
func serve(t *testing.T, f *fixture, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response headers: %v", w.Header())
	}
	return w
}
func rejected(t *testing.T, w *httptest.ResponseRecorder, code string, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d: %s", w.Code, status, w.Body)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 3 || string(body["code"]) != strconv.Quote(code) || string(body["details"]) != "{}" {
		t.Fatalf("refusal shape: %s", w.Body)
	}
	var message string
	if err := json.Unmarshal(body["message"], &message); err != nil || message == "" {
		t.Fatal("safe summary missing")
	}
	for _, secret := range []string{"EXAMPLE_BEARER", "/sensitive/example", "request-secret", "eyJhbGci"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("request/bearer detail in refusal")
		}
	}
	if status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "POST" {
		t.Fatal("missing Allow: POST")
	}
}
func unverifiedAudit(t *testing.T, f *fixture, code string, observed int) {
	t.Helper()
	events := f.audit.events(t)
	if len(events) != 1 {
		t.Fatalf("audit count %d", len(events))
	}
	e := events[0]
	if e["code"] != code || e["outcome"] != "refused" || e["request_bytes"] != float64(observed) {
		t.Fatal(e)
	}
	for _, field := range []string{"jti", "key_id", "host", "name", "registry_revision", "jwt_iat", "jwt_exp"} {
		if e[field] != nil {
			t.Fatalf("unverified %s: %v", field, e[field])
		}
	}
	if len(f.audit.acks) != 1 || !bytes.Equal(f.audit.acks[0], f.audit.lines[0]) {
		t.Fatal("early refusal not acknowledged exactly")
	}
}
func expectedJWT(t *testing.T, raw []byte) string {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "swarma-registrar", "aud": []string{"example.org"}, "sub": "host-a_project_role", "iat": testEpoch + 100, "nbf": testEpoch + 100, "exp": testEpoch + 220, "jti": e["id"]}
	// ASCII/integer-only claims make encoding/json an independent canonical-byte
	// oracle here; no admission or CCJ writer is reused for the expected JWT.
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	prefix := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return prefix + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(testPrivate(9), []byte(prefix)))
}
func accepted(t *testing.T, f *fixture, raw []byte) {
	t.Helper()
	w := serve(t, f, request(raw))
	if w.Code != 200 {
		t.Fatalf("positive control: %d %s", w.Code, w.Body)
	}
	want, _ := json.Marshal(map[string]string{"jwt": expectedJWT(t, raw)})
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("JWT response mismatch: %s", w.Body)
	}
	events := f.audit.events(t)
	last := events[len(events)-1]
	if last["outcome"] != "issued" || last["http_status"] != float64(200) {
		t.Fatal(last)
	}
	if len(f.audit.acks) != len(f.audit.lines) || !bytes.Equal(f.audit.acks[len(f.audit.acks)-1], f.audit.lines[len(f.audit.lines)-1]) {
		t.Fatal("release without exact audit ack")
	}
}

// Every rows 1–7 refusal has exact status, fixed JSON shape, no-store headers and
// a null-identity audit. Same-pair success at capacity one proves no early charge
// or nonce reservation; P-256 controls exercise the real low-S/equation path.
func TestEarlyRefusals(t *testing.T) {
	for _, kind := range []string{"endpoint", "method", "oversize", "media", "malformed", "id", "point", "high S", "equation"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			good := validProof(t, 1)
			raw := bytes.Clone(good)
			code := ""
			status := 0
			switch kind {
			case "endpoint":
				code = "endpoint_not_found"
				status = 404
			case "method":
				code = "method_not_allowed"
				status = 405
			case "oversize":
				code = "request_too_large"
				status = 413
				raw = bytes.Repeat([]byte{'x'}, 65537)
			case "media":
				code = "unsupported_media_type"
				status = 415
			case "malformed":
				code = "registration_malformed"
				status = 400
				raw = []byte(`request-secret EXAMPLE_BEARER /sensitive/example`)
			case "id":
				code = "registration_id_mismatch"
				status = 400
				raw = editEnvelope(t, raw, func(e map[string]any) { e["id"] = "sha256:" + strings.Repeat("0", 64) })
			case "point":
				code = "registration_signature_invalid"
				status = 403
				raw = signed(t, envelope.Registration, proofBody("ed25519:AA", 1), 2)
			case "high S":
				code = "signature_high_s"
				status = 403
				var key string
				raw, key = p256Proof(t, true, false, false)
				good, _ = p256Proof(t, false, false, false)
				f.core.Publish(snapshotFixture(t, key, "active"))
			case "equation":
				code = "registration_signature_invalid"
				status = 403
				raw = editEnvelope(t, raw, func(e map[string]any) { e["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) })
			}
			r := request(raw)
			observed := len(raw)
			if kind == "endpoint" {
				r.URL.Path = "/unknown"
				observed = 0
			}
			if kind == "method" {
				r.Method = "GET"
				observed = 0
			}
			if kind == "media" {
				r.Header.Set("Content-Type", "text/plain")
			}
			rejected(t, serve(t, f, r), code, status)
			unverifiedAudit(t, f, code, observed)
			accepted(t, f, good)
		})
	}
}

type forbiddenRead struct{ t *testing.T }

func (r forbiddenRead) Read([]byte) (int, error) {
	r.t.Fatal("routing/method refusal read the body")
	return 0, io.EOF
}
func (forbiddenRead) Close() error { return nil }

// Adjacent multi-defect cases select the first row, including the split key,
// range, low-S and equation checks. Positive controls never bypass parsing.
func TestAdjacentOrder(t *testing.T) {
	for _, pair := range []string{"1 before 2", "2 before 3", "3 before 4", "4 before 5", "5 before 6", "6 before 7a", "7a before 7b", "7b before 7c", "7c before 8"} {
		t.Run(pair, func(t *testing.T) {
			f := setup(t)
			raw := validProof(t, 1)
			r := request(raw)
			code := ""
			status := 0
			switch pair {
			case "1 before 2":
				r.URL.Path = "/unknown"
				r.Method = "GET"
				r.Body = forbiddenRead{t}
				code = "endpoint_not_found"
				status = 404
			case "2 before 3":
				r.Method = "GET"
				r.Body = forbiddenRead{t}
				r.ContentLength = 65537
				code = "method_not_allowed"
				status = 405
			case "3 before 4":
				r = request(bytes.Repeat([]byte{'x'}, 65537))
				r.Header.Set("Content-Type", "text/plain")
				code = "request_too_large"
				status = 413
			case "4 before 5":
				r = request([]byte("{"))
				r.Header.Set("Content-Type", "text/plain")
				code = "unsupported_media_type"
				status = 415
			case "5 before 6":
				r = request(editEnvelope(t, raw, func(e map[string]any) {
					e["id"] = "sha256:" + strings.Repeat("0", 64)
					e["body"].(map[string]any)["nonce"] = "AA"
				}))
				code = "registration_malformed"
				status = 400
			case "6 before 7a":
				raw = signed(t, envelope.Registration, proofBody("ed25519:AA", 1), 2)
				r = request(editEnvelope(t, raw, func(e map[string]any) { e["id"] = "sha256:" + strings.Repeat("0", 64) }))
				code = "registration_id_mismatch"
				status = 400
			case "7a before 7b":
				raw, _ = p256Proof(t, true, true, false)
				r = request(raw)
				code = "registration_signature_invalid"
				status = 403
			case "7b before 7c":
				raw, _ = p256Proof(t, true, false, true)
				r = request(raw)
				code = "signature_high_s"
				status = 403
			case "7c before 8":
				r = request(editEnvelope(t, raw, func(e map[string]any) { e["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) }))
				f.core.Publish(nil)
				code = "registration_signature_invalid"
				status = 403
			}
			rejected(t, serve(t, f, r), code, status)
			g := setup(t)
			accepted(t, g, validProof(t, 1))
		})
	}
}

// Only one supported media value and identity encoding reach parsing; case
// changes preserve token meaning. No case asserts unspecified whitespace rules.
func TestMedia(t *testing.T) {
	for _, tc := range []struct {
		name             string
		types, encodings []string
	}{
		{"missing type", nil, nil}, {"empty type", []string{""}, nil}, {"wrong type", []string{"text/plain"}, nil},
		{"wrong charset", []string{"application/json;charset=latin1"}, nil}, {"other parameter", []string{"application/json;boundary=x"}, nil},
		{"extra parameter", []string{"application/json;charset=utf-8;boundary=x"}, nil},
		{"second equal type", []string{"application/json", "application/json"}, nil},
		{"second different type", []string{"application/json", "text/plain"}, nil},
		{"joined types", []string{"application/json,application/json"}, nil},
		{"gzip", []string{"application/json"}, []string{"gzip"}},
		{"empty encoding", []string{"application/json"}, []string{""}},
		{"encoding list", []string{"application/json"}, []string{"identity,gzip"}},
		{"second encoding", []string{"application/json"}, []string{"identity", "identity"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			raw := validProof(t, 1)
			r := request(raw)
			r.Header["Content-Type"] = tc.types
			r.Header["Content-Encoding"] = tc.encodings
			rejected(t, serve(t, f, r), "unsupported_media_type", 415)
			unverifiedAudit(t, f, "unsupported_media_type", len(raw))
			accepted(t, f, raw)
		})
	}
	for _, media := range []string{"application/json", "APPLICATION/JSON", "application/json;charset=utf-8", "Application/Json;CHARSET=UtF-8"} {
		f := setup(t)
		raw := validProof(t, 1)
		r := request(raw)
		r.Header.Set("Content-Type", media)
		r.Header.Set("Content-Encoding", "IDENTITY")
		w := serve(t, f, r)
		if w.Code != 200 {
			t.Fatalf("valid tokens %q: %d %s", media, w.Code, w.Body)
		}
		want, _ := json.Marshal(map[string]string{"jwt": expectedJWT(t, raw)})
		if !bytes.Equal(w.Body.Bytes(), want) {
			t.Fatal("JWT body")
		}
	}
}

type capBody struct {
	t    *testing.T
	data []byte
	read int
}

func (b *capBody) Read(p []byte) (int, error) {
	if b.read >= 65537 || len(p) > 65537-b.read {
		b.t.Fatal("attempt to read past cap+1")
	}
	n := copy(p, b.data[b.read:])
	b.read += n
	if b.read == len(b.data) {
		return n, io.EOF
	}
	return n, nil
}
func (*capBody) Close() error { return nil }

// Received bytes, not Content-Length, determine the cap; the underlying reader
// never receives a read beyond cap+1. Exactly cap bytes of valid JSON still pass.
func TestStreamingCap(t *testing.T) {
	for _, length := range []int64{-1, 1, 1 << 30} {
		f := setup(t)
		b := &capBody{t: t, data: bytes.Repeat([]byte{'x'}, 70000)}
		r := request(nil)
		r.Body = b
		r.ContentLength = length
		rejected(t, serve(t, f, r), "request_too_large", 413)
		if b.read != 65537 {
			t.Fatal(b.read)
		}
		unverifiedAudit(t, f, "request_too_large", 65537)
		accepted(t, f, validProof(t, 1))
	}
	f := setup(t)
	raw := validProof(t, 1)
	raw = append(raw, bytes.Repeat([]byte{' '}, 65536-len(raw))...)
	b := &capBody{t: t, data: raw}
	r := request(nil)
	r.Body = b
	r.ContentLength = -1
	w := serve(t, f, r)
	if w.Code != 200 || b.read != 65536 {
		t.Fatalf("exact cap: %d, %d", w.Code, b.read)
	}
	want, _ := json.Marshal(map[string]string{"jwt": expectedJWT(t, raw)})
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal("exact-cap JWT")
	}
	// A dishonest large declared length cannot turn a small valid received body
	// into an oversize refusal inside this handler.
	g := setup(t)
	good := validProof(t, 1)
	r = request(good)
	r.ContentLength = 1 << 30
	w = serve(t, g, r)
	want, _ = json.Marshal(map[string]string{"jwt": expectedJWT(t, good)})
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatal("trusted declared length")
	}
}

type failedBody struct{}

func (failedBody) Read([]byte) (int, error) {
	return 0, errors.New("request-secret /sensitive/example")
}
func (failedBody) Close() error { return nil }

// Read failure cannot leak its diagnostic and is deferred until row 5; media
// still precedes interpretation. Nil/empty bodies are malformed, not panics.
func TestReadFailures(t *testing.T) {
	for _, kind := range []string{"read failure", "media plus read failure", "nil body", "empty body"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			r := request(nil)
			code := "registration_malformed"
			status := 400
			switch kind {
			case "read failure":
				r.Body = failedBody{}
			case "media plus read failure":
				r.Body = failedBody{}
				r.Header.Set("Content-Type", "text/plain")
				code = "unsupported_media_type"
				status = 415
			case "nil body":
				r.Body = nil
			}
			rejected(t, serve(t, f, r), code, status)
			unverifiedAudit(t, f, code, 0)
			accepted(t, f, validProof(t, 1))
		})
	}
}

// Local audit failure overrides every early refusal; no original code or JWT
// leaks, and a healthy independent process remains able to issue normally.
func TestEarlyAuditOverride(t *testing.T) {
	for _, kind := range []string{"endpoint", "method", "oversize", "media", "malformed", "id", "signature"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			f.audit.fail = true
			raw := validProof(t, 1)
			r := request(raw)
			switch kind {
			case "endpoint":
				r.URL.Path = "/unknown"
			case "method":
				r.Method = "GET"
			case "oversize":
				r = request(bytes.Repeat([]byte{'x'}, 65537))
			case "media":
				r.Header.Set("Content-Type", "text/plain")
			case "malformed":
				r = request([]byte("{"))
			case "id":
				r = request(editEnvelope(t, raw, func(e map[string]any) { e["id"] = "sha256:" + strings.Repeat("0", 64) }))
			case "signature":
				r = request(editEnvelope(t, raw, func(e map[string]any) { e["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) }))
			}
			rejected(t, serve(t, f, r), "audit_unavailable", 503)
			if f.core.Ready() || len(f.audit.lines) != 0 {
				t.Fatal("false recording readiness")
			}
			g := setup(t)
			accepted(t, g, validProof(t, 1))
		})
	}
}

// Admission refusals retain their protocol statuses and safe response shape;
// rate-limit responses preserve Retry-After and replay is a 409 conflict.
func TestAdmissionResponses(t *testing.T) {
	for _, kind := range []string{"registry", "key", "window", "revoked", "name", "permission", "audience", "clock", "future", "expired", "limit", "replay", "signer", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			raw := validProof(t, 1)
			body := proofBody(testPublic(2), 1)
			code := ""
			status := 403
			switch kind {
			case "registry":
				f.core.Publish(nil)
				code = "registry_unavailable"
				status = 503
			case "key":
				f.core.Publish(snapshotFixture(t, testPublic(3), "active"))
				code = "key_not_enrolled"
			case "window":
				body["iat"] = "2031-01-01T00:00:00Z"
				body["exp"] = "2031-01-01T00:00:20Z"
				raw = signed(t, envelope.Registration, body, 2)
				code = "key_not_valid_now"
			case "revoked":
				f.core.Publish(snapshotFixture(t, testPublic(2), "revoked"))
				code = "host_revoked"
			case "name":
				body["name"] = "Upper"
				raw = signed(t, envelope.Registration, body, 2)
				code = "name_invalid"
				status = 400
			case "permission":
				body["name"] = "host-b_project_role"
				raw = signed(t, envelope.Registration, body, 2)
				code = "name_not_permitted"
			case "audience":
				body["aud"] = "other.example"
				raw = signed(t, envelope.Registration, body, 2)
				code = "audience_mismatch"
			case "clock":
				f.clock.healthy = false
				code = "clock_skew"
				status = 400
			case "future":
				body["iat"] = "2030-01-01T00:02:11Z"
				body["exp"] = "2030-01-01T00:02:30Z"
				raw = signed(t, envelope.Registration, body, 2)
				code = "request_not_yet_valid"
			case "expired":
				body["iat"] = "2030-01-01T00:00:31Z"
				body["exp"] = "2030-01-01T00:01:10Z"
				raw = signed(t, envelope.Registration, body, 2)
				code = "request_expired"
			case "limit":
				accepted(t, f, raw)
				raw = validProof(t, 2)
				code = "rate_limited"
				status = 429
			case "replay":
				f = setupLimits(t, 2, 2)
				accepted(t, f, raw)
				body["name"] = "host-a_another_role"
				raw = signed(t, envelope.Registration, body, 2)
				code = "nonce_replayed"
				status = 409
			case "signer":
				f.signer.fail = true
				code = "service_unavailable"
				status = 503
			case "audit":
				f.audit.ackFail = true
				code = "audit_unavailable"
				status = 503
			}
			w := serve(t, f, request(raw))
			rejected(t, w, code, status)
			if kind == "limit" && w.Header().Get("Retry-After") != "60" {
				t.Fatal("retry delay")
			}
			events := f.audit.events(t)
			if events[len(events)-1]["code"] != code {
				t.Fatal("missing refusal audit")
			}
			g := setup(t)
			accepted(t, g, validProof(t, 1))
		})
	}
}

// Construction rejects a missing audit/admission dependency; a configured
// handler passes a complete registration through parsing, signing and audit.
func TestConstructionAndSuccess(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil core accepted")
	}
	f := setup(t)
	accepted(t, f, validProof(t, 1))
}

// A locally recorded early refusal may spool when off-host acknowledgement is
// unavailable; that outage still forbids issuance in the admission core.
func TestEarlyRefusalSpooling(t *testing.T) {
	f := setup(t)
	f.audit.ackFail = true
	rejected(t, serve(t, f, request([]byte("{"))), "registration_malformed", 400)
	events := f.audit.events(t)
	if len(events) != 1 || events[0]["code"] != "registration_malformed" || len(f.audit.acks) != 0 {
		t.Fatal("refusal not locally spooled")
	}
	rejected(t, serve(t, f, request(validProof(t, 1))), "audit_unavailable", 503)
	g := setup(t)
	accepted(t, g, validProof(t, 1))
}
