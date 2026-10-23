package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func reviewerVector(t *testing.T, id string) admissionVector {
	t.Helper()
	files, err := filepath.Glob("../../vectors/registration-1/*/" + id + ".json")
	if err != nil || len(files) != 1 {
		t.Fatal("fixture unavailable")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var v admissionVector
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func reviewerRun(t *testing.T, v admissionVector) *admissionRun {
	t.Helper()
	var seeds struct {
		JWT      string `json:"registrar_jwt"`
		TestOnly bool   `json:"test_only"`
	}
	raw, err := os.ReadFile("../../vectors/keys/seeds.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &seeds); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(seeds.JWT)
	if err != nil || !seeds.TestOnly || len(seed) != 32 {
		t.Fatal("published test seed unavailable")
	}
	spec := readSpec(t, "../../spec/registrar.md")
	return newAdmissionRun(t, v, spec[v.Row], ed25519.NewKeyFromSeed(seed))
}
func reviewerHTTP(t *testing.T, r *admissionRun, raw []byte, want string) {
	t.Helper()
	q := httptest.NewRequest(r.v.Fixture.HTTP.Method, r.v.Fixture.HTTP.Path, bytes.NewReader(raw))
	q.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.handler.ServeHTTP(rr, q)
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := "accept"
	if e, ok := body["code"].(string); ok {
		got = e
	}
	if got != want || rr.Code != admissionStatus(want) {
		t.Fatalf("response status=%d code=%s; want status=%d code=%s", rr.Code, got, admissionStatus(want), want)
	}
	if want != "accept" {
		if _, ok := body["jwt"]; ok {
			t.Fatal("refusal released JWT")
		}
	}
}

// Missing rollback evidence refuses the unchanged PR1 proof and publishes no
// authority or accounting. The healthy PR1 remains the nearby positive control.
func TestReviewerRollbackEvidence(t *testing.T) {
	v := reviewerVector(t, "PR1")
	v.Fixture.Registry.RollbackStateAvailable = false
	r := reviewerRun(t, v)
	raw := decodeExpected(t, v.Input.Bytes)
	reviewerHTTP(t, r, raw, "registry_unavailable")
	if r.snapshot != nil || r.store.water != nil || r.core.Ready() {
		t.Fatal("missing rollback evidence published authority or left admission ready")
	}
	r.expectAudit(t, raw, "registry_unavailable", v.Fixture.Now, 0, nil)
	r.disagree(t, "rollback refusal audit", admissionLineStrings(r.audit.lines), admissionLineStrings(r.wantLines))
	r.v.Expected.State.RegistryReady = false
	r.v.Expected.State.NonceCache = v.Fixture.NonceCache
	r.v.Expected.State.LimiterEvents = v.Fixture.LimiterEvents
	r.v.Expected.State.AuditOutcomes = []string{"registry_unavailable"}
	r.checkState(t)
}

// These mutations originate from a successful row and exercise the real HTTP entry point.
func TestReviewerFixtureFaults(t *testing.T) {
	for _, id := range []string{"healthy", "unhealthy_startup", "fenced_process", "failed_ack", "wrong_generation", "revoked_mid_request"} {
		t.Run(id, func(t *testing.T) {
			v := reviewerVector(t, "PR1")
			want := "accept"
			switch id {
			case "unhealthy_startup":
				v.Fixture.StartupVerified = false
				want = "clock_skew"
			case "fenced_process":
				v.Fixture.ClockFenced = true
				want = "clock_skew"
			case "failed_ack":
				v.Fixture.Audit.RemoteAck = false
				want = "audit_unavailable"
			}
			if id == "wrong_generation" {
				v.Fixture.PostAuditGeneration = "B"
				v.Expected = reviewerVector(t, "R128").Expected
				r := reviewerRun(t, v)
				r.request(t, v.Input.Bytes, v.Fixture.Now, v.Expected, true)
				r.checkState(t)
				return
			}
			if id == "revoked_mid_request" {
				other := reviewerVector(t, "R123")
				v.Fixture.PostAuditRevoked = true
				v.Fixture.ScheduledRegistry = other.Fixture.ScheduledRegistry
				v.Expected = other.Expected
				r := reviewerRun(t, v)
				r.request(t, v.Input.Bytes, v.Fixture.Now, v.Expected, true)
				r.checkState(t)
				return
			}
			r := reviewerRun(t, v)
			reviewerHTTP(t, r, decodeExpected(t, v.Input.Bytes), want)
		})
	}
}

// R105's exact nonce and budget seed is reachable by an issued request and two replay refusals.
// The three prefix audit lines are retained and checked; the main attempt's audit is checked separately.
func TestReviewerR105Reachability(t *testing.T) {
	v := reviewerVector(t, "R105")
	r := reviewerRun(t, v)
	raw := decodeExpected(t, v.Input.Bytes)
	var e struct{ Body map[string]any }
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	epoch := v.Fixture.Now - 60
	e.Body["iat"] = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	e.Body["exp"] = time.Unix(epoch+120, 0).UTC().Format(time.RFC3339)
	// RFC 8032 public vector material already published by this repository.
	var seeds map[string]json.RawMessage
	seedFile, err := os.ReadFile("../../vectors/keys/seeds.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(seedFile, &seeds); err != nil {
		t.Fatal(err)
	}
	var priv ed25519.PrivateKey
	for _, value := range seeds {
		var s string
		if json.Unmarshal(value, &s) != nil {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			continue
		}
		k := ed25519.NewKeyFromSeed(b)
		if "ed25519:"+base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey)) == e.Body["key"] {
			priv = k
		}
	}
	if priv == nil {
		t.Fatal("published host test seed not found")
	}
	pre, id, err := envelope.SigningInput(envelope.Registration, e.Body)
	if err != nil {
		t.Fatal(err)
	}
	preRaw, err := ccj.Marshal(map[string]any{"body": e.Body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, pre))}, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.reading.UTC = epoch + 1
	r.clock.reading.Monotonic = time.Second
	reviewerHTTP(t, r, preRaw, "accept")
	reviewerHTTP(t, r, preRaw, "nonce_replayed")
	reviewerHTTP(t, r, preRaw, "nonce_replayed")
	r.v.Expected.State.NonceCache = v.Fixture.NonceCache
	r.v.Expected.State.LimiterEvents = v.Fixture.LimiterEvents
	r.v.Expected.State.AuditOutcomes = []string{"issued", "nonce_replayed", "nonce_replayed"}
	r.checkState(t)
	if t.Failed() {
		return
	}
	t.Log("Exact R105 initial accounting reached through three HTTP requests; prefix audit retained")
	r.v.Expected = v.Expected
	r.v.Expected.State.AuditOutcomes = append([]string{"issued", "nonce_replayed", "nonce_replayed"}, v.Expected.State.AuditOutcomes...)
	r.clock.reading.UTC = v.Fixture.Now
	r.clock.reading.Monotonic = time.Duration(v.Fixture.MonotonicNow) * time.Second
	reviewerHTTP(t, r, raw, v.Expected.Code)
	r.checkState(t)
	if t.Failed() {
		return
	}
	t.Log("Original R105 rate_limited verdict and exact final accounting hold; chained audit has three prefix lines plus original main outcome")
	if pending := admissionPending(v); pending != "" {
		t.Errorf("reachable R105 still skipped: %s", pending)
	}
}
