package conformance_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/httpapi"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/registry"
)

type admissionExpected struct {
	Code  string
	JWT   *struct{ Compact string }
	State struct {
		NonceCache                 []admissionNonce `json:"nonce_cache"`
		LimiterEvents              []admissionEvent `json:"limiter_events"`
		AuditOutcomes              []string         `json:"audit_outcomes"`
		ClockFenced                bool             `json:"clock_fenced"`
		StartBarrier               int64            `json:"start_barrier"`
		SignerReady                bool             `json:"signer_ready"`
		AuditReady                 bool             `json:"audit_ready"`
		RegistryReady              bool             `json:"registry_ready"`
		SigningGeneration          string           `json:"signing_generation"`
		ScheduledRevocationApplied bool             `json:"scheduled_revocation_applied"`
		Authority                  struct {
			RecordIDs []string `json:"record_ids"`
			Revision  string
		}
	}
	AuditLine string `json:"audit_line_base64"`
	AuditHash string `json:"audit_line_sha256"`
}

type admissionNonce struct {
	Key, Nonce string
	Expires    int64
}
type admissionEvent struct {
	At        int64
	Key, Name string
}
type admissionRegistry struct {
	Available, Approved, Descendant bool
	CommitSignatureValid            bool     `json:"commit_signature_valid"`
	PinIsExact                      bool     `json:"pin_is_exact"`
	PersistAvailable                bool     `json:"persist_available"`
	RollbackStateAvailable          bool     `json:"rollback_state_available"`
	PublisherKey                    string   `json:"publisher_key"`
	StationHosts                    []string `json:"station_hosts"`
	Revision                        string
	Files                           []struct {
		Path, Kind string
		Repeat     int
		Bytes      string `json:"bytes_base64"`
	}
}
type admissionVector struct {
	Row, Domain, Mode string
	Input             struct {
		Bytes string `json:"bytes_base64"`
	}
	Fixture struct {
		Audience          string
		Now               int64
		MonotonicNow      int64            `json:"monotonic_now"`
		ActualStartMillis int64            `json:"actual_start_millis"`
		StartBarrier      int64            `json:"start_barrier"`
		StartupVerified   bool             `json:"startup_verified"`
		ClockHealthy      bool             `json:"clock_healthy"`
		ClockFenced       bool             `json:"clock_fenced"`
		SignerAvailable   bool             `json:"signer_available"`
		SigningGeneration string           `json:"signing_generation"`
		NonceCache        []admissionNonce `json:"nonce_cache"`
		LimiterEvents     []admissionEvent `json:"limiter_events"`
		KeyCapacity       int              `json:"key_capacity"`
		NameCapacity      int              `json:"name_capacity"`
		Audit             struct {
			LocalAvailable bool `json:"local_available"`
			RemoteAck      bool `json:"remote_ack"`
		}
		HTTP struct {
			Path, Method         string
			ContentType          string `json:"content_type"`
			ContentEncoding      string `json:"content_encoding"`
			ContentLengthPresent *bool  `json:"content_length_present"`
		}
		Registry            admissionRegistry
		ScheduledRegistry   *admissionRegistry `json:"scheduled_registry"`
		FinalRevoked        bool               `json:"final_revoked"`
		PostAuditRevoked    bool               `json:"post_audit_revoked"`
		PostAuditGeneration string             `json:"post_audit_generation"`
		FinalNow            *int64             `json:"final_now"`
	}
	Before, After []admissionTransition
	Expected      admissionExpected
}
type admissionTransition struct {
	Event              string
	Now                int64
	Healthy, Available bool
	ActualStartMillis  int64  `json:"actual_start_millis"`
	StartupVerified    bool   `json:"startup_verified"`
	Bytes              string `json:"bytes_base64"`
	Expected           admissionExpected
}

// This is an additional end-to-end classification. The legacy prefix test is
// unchanged and still reports its own historical stage-pending classifications.
// Accepted rows prove exact JWT bytes; refused neighbors prove no JWT response,
// exact accounting, and the audit oracle. No live adapter is qualified here.
func TestAdmissionVectorConformance(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(cwd, "..", ".."))
	vectorRoot := os.Getenv("CONFORMANCE_VECTORS")
	if vectorRoot == "" {
		vectorRoot = filepath.Join(root, "vectors")
	}
	spec := readSpec(t, filepath.Join(root, "spec", "registrar.md"))
	var seeds struct {
		JWT      string `json:"registrar_jwt"`
		TestOnly bool   `json:"test_only"`
	}
	seedJSON, err := os.ReadFile(filepath.Join(vectorRoot, "keys", "seeds.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(seedJSON, &seeds); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(seeds.JWT)
	if err != nil || !seeds.TestOnly || len(seed) != ed25519.SeedSize {
		t.Fatal("expected published JWT test seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	var total counts
	seen := map[string]bool{}
	for _, file := range vectorFiles(t, filepath.Join(vectorRoot, "registration-1")) {
		var v admissionVector
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		row, ok := spec[v.Row]
		if !ok || row.domain != "registration/1" || v.Domain != row.domain || v.Mode != "admission" || filepath.Base(file) != v.Row+".json" || seen[v.Row] {
			t.Fatalf("invalid registration row %s", file)
		}
		seen[v.Row] = true
		pending := admissionPending(v)
		ran := false
		passed := t.Run(v.Row, func(t *testing.T) {
			ran = true
			if pending != "" {
				t.Skipf("stage-pending %s: %s; spec/registrar.md:%d", v.Row, pending, row.line)
			}
			run := newAdmissionRun(t, v, row, key)
			run.establishAccounting(t, vectorRoot)
			for _, step := range v.Before {
				run.transition(t, step)
			}
			run.request(t, v.Input.Bytes, v.Fixture.Now, v.Expected, true)
			for _, step := range v.After {
				run.transition(t, step)
			}
			run.checkState(t)
		})
		if !ran {
			continue // A subtest excluded by -run supplies no passing evidence.
		}
		switch {
		case !passed:
			total.fail++
		case pending != "":
			total.pending++
		default:
			total.pass++
		}
	}
	for id, row := range spec {
		if row.domain == "registration/1" && !seen[id] {
			t.Errorf("registration vector missing: %s", id)
		}
	}
	t.Logf("ADMISSION COUNTS registration/1: pass=%d fail=%d pending=%d", total.pass, total.fail, total.pending)
}

// These literal states cannot be produced through the request API: reservation
// follows both debits; pruning retains or inserts a nonce; restart clears both.
// R105 instead has a declared generating prefix, executed below without writes
// to private state. Unknown nonempty states fail rather than becoming pending.
var admissionPendingReasons = map[string]string{
	"R83":  "retained nonce with zero limiter events; reservation requires both budget debits and restart clears both",
	"R84":  "retained nonce with zero limiter events; reservation requires both budget debits and restart clears both",
	"PR18": "retained nonce with zero limiter events; reservation requires both budget debits and restart clears both",
	"R86":  "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
	"R87":  "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
	"R111": "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
	"R129": "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
	"PR13": "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
	"PR14": "limiter events without a nonce; reservation retains or inserts a pair, clock advance alone does not sweep, restart clears both",
}

func admissionPending(v admissionVector) string {
	return admissionPendingReasons[v.Row]
}

// R105's declared public prehistory reaches one nonce (expiry 00:02:30) and
// three attempts at monotonic second 1: one issuance, then two replays. Keep
// every prefix audit line and verify the literal initial accounting before
// advancing to the unchanged main request at UTC/monotonic second 60.
func (r *admissionRun) establishAccounting(t *testing.T, vectorRoot string) {
	t.Helper()
	f := r.v.Fixture
	if r.v.Row != "R105" {
		if len(f.NonceCache) != 0 || len(f.LimiterEvents) != 0 {
			t.Fatal("nonempty accounting fixture lacks a declared prefix or per-row pending reason")
		}
		return
	}
	var input struct{ Body map[string]any }
	if err := json.Unmarshal(decodeExpected(t, r.v.Input.Bytes), &input); err != nil {
		t.Fatal(err)
	}
	// Read only the fixed, published host seed; never deployment key material.
	var seeds struct {
		Host     string `json:"host_ed25519"`
		TestOnly bool   `json:"test_only"`
	}
	rawSeeds, err := os.ReadFile(filepath.Join(vectorRoot, "keys", "seeds.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawSeeds, &seeds); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(seeds.Host)
	if err != nil || !seeds.TestOnly || len(seed) != ed25519.SeedSize {
		t.Fatal("expected published host test seed")
	}
	hostKey := ed25519.NewKeyFromSeed(seed)
	if input.Body["key"] != "ed25519:"+base64.RawURLEncoding.EncodeToString(hostKey.Public().(ed25519.PublicKey)) {
		t.Fatal("prefix host test key differs from fixture")
	}
	epoch := f.Now - 60
	input.Body["iat"] = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	input.Body["exp"] = time.Unix(epoch+120, 0).UTC().Format(time.RFC3339)
	preimage, id, err := envelope.SigningInput(envelope.Registration, input.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": input.Body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(hostKey, preimage))}, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}

	// The prefix's JWT oracle is fixed by §8 and this declared request; it is
	// independent of the Handler response and production JWT construction.
	at := epoch + 1
	header, err := ccj.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT"}, refusal.ServiceUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ccj.Marshal(map[string]any{"iss": "swarma-registrar", "aud": []any{f.Audience}, "sub": input.Body["name"], "iat": at, "nbf": at, "exp": at + 120, "jti": id}, refusal.ServiceUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	issued := admissionExpected{Code: "accept", JWT: &struct{ Compact string }{signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(r.signer.key, []byte(signingInput)))}}
	r.clock.reading.Monotonic = time.Second
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	r.request(t, encoded, at, issued, false)
	for i := 0; i < 2; i++ {
		r.request(t, encoded, at, admissionExpected{Code: "nonce_replayed"}, false)
	}
	r.checkAccounting(t, f.NonceCache, f.LimiterEvents)
	r.disagree(t, "R105 prefix audit count", len(r.audit.lines), 3)
	r.v.Expected.State.AuditOutcomes = append([]string{"issued", "nonce_replayed", "nonce_replayed"}, r.v.Expected.State.AuditOutcomes...)
	r.clock.reading.UTC = f.Now
	r.clock.reading.Monotonic = time.Duration(f.MonotonicNow) * time.Second
}

type admissionClock struct{ reading admission.Reading }

func (c *admissionClock) Now() admission.Reading { return c.reading }

// All fixture operations terminate synchronously. The real monotonic timeout
// bounds accidental stalls and preserves cancellation; virtual clock advances
// in these rows are UTC evidence, not simulated watchdog expiry.
func (c *admissionClock) Deadline(ctx context.Context, at time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, at-c.reading.Monotonic)
}

type admissionSigner struct {
	key        ed25519.PrivateKey
	available  bool
	duringSign func()
}

func (s *admissionSigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }
func (s *admissionSigner) Sign(ctx context.Context, raw []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !s.available {
		return nil, errors.New("fixture signer unavailable")
	}
	if s.duringSign != nil {
		f := s.duringSign
		s.duringSign = nil
		f()
	}
	return ed25519.Sign(s.key, raw), nil
}

type admissionAudit struct {
	local, remote bool
	lines, acks   [][]byte
	duringAck     func()
}

func (a *admissionAudit) Append(ctx context.Context, line []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !a.local {
		return errors.New("fixture local append unavailable")
	}
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		return err
	}
	previous := strings.Repeat("0", 64)
	if len(a.lines) > 0 {
		previous = admissionHash(a.lines[len(a.lines)-1])
	}
	if event["seq"] != float64(len(a.lines)+1) || event["prev_hash"] != previous || !bytes.HasSuffix(line, []byte{'\n'}) {
		return errors.New("fixture audit continuity violation")
	}
	a.lines = append(a.lines, bytes.Clone(line))
	return nil
}
func (a *admissionAudit) Acknowledge(ctx context.Context, line []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !a.remote {
		return errors.New("fixture off-host acknowledgement unavailable")
	}
	if len(a.lines) == 0 || !bytes.Equal(line, a.lines[len(a.lines)-1]) {
		return errors.New("acknowledgement differs from committed line")
	}
	if a.duringAck != nil {
		f := a.duringAck
		a.duringAck = nil
		f()
	}
	a.acks = append(a.acks, bytes.Clone(line))
	return nil
}
func (a *admissionAudit) Probe(ctx context.Context, h admission.AuditHead) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	want := admission.AuditHead{Hash: strings.Repeat("0", 64)}
	if len(a.lines) > 0 {
		want = admission.AuditHead{Sequence: int64(len(a.lines)), Hash: admissionHash(a.lines[len(a.lines)-1])}
	}
	if !a.local || h != want {
		return errors.New("fixture retained audit head unavailable")
	}
	return nil
}
func admissionHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

type admissionTrust struct {
	fixture admissionRegistry
	entries []registry.Entry
}

func (v admissionTrust) Verify(revision string, entries []registry.Entry) error {
	f := v.fixture
	if !f.Available || !f.Approved || !f.CommitSignatureValid || !f.PinIsExact || revision != f.Revision || !reflect.DeepEqual(entries, v.entries) {
		return errors.New("fixture exact approved revision unavailable")
	}
	return nil
}
func (v admissionTrust) Descends(candidate, previous string) (bool, error) {
	if !v.fixture.Available {
		return false, errors.New("fixture ancestry unavailable")
	}
	return v.fixture.Descendant, nil
}

type admissionStore struct {
	water     *registry.HighWater
	available bool
}

func (s *admissionStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if !s.available || !reflect.DeepEqual(s.water, previous) {
		return errors.New("fixture persistence unavailable or stale")
	}
	s.water = next.Clone()
	return nil
}

type admissionRun struct {
	v             admissionVector
	spec          specRow
	clock         *admissionClock
	signer        *admissionSigner
	audit         *admissionAudit
	store         *admissionStore
	snapshot      *registry.Snapshot
	core          *admission.Admitter
	handler       *httpapi.Handler
	instance      [16]byte
	revoked       bool
	wantLines     [][]byte
	lastAdmission *int64
}

func newAdmissionRun(t *testing.T, v admissionVector, row specRow, key ed25519.PrivateKey) *admissionRun {
	t.Helper()
	f := v.Fixture
	r := &admissionRun{v: v, spec: row,
		clock:  &admissionClock{admission.Reading{UTC: f.Now, Monotonic: time.Duration(f.MonotonicNow) * time.Second, Healthy: f.ClockHealthy, Faulted: f.ClockFenced}},
		signer: &admissionSigner{key: key, available: f.SignerAvailable},
		audit:  &admissionAudit{local: f.Audit.LocalAvailable, remote: f.Audit.RemoteAck}, store: &admissionStore{}}
	for i := range r.instance {
		r.instance[i] = byte(32 + i)
	}
	r.snapshot = r.load(t, f.Registry, true)
	if f.StartBarrier != f.ActualStartMillis/1000+31 || f.SigningGeneration != "A" {
		t.Fatal("unsupported startup/generation fixture")
	}
	r.start(t, f.ActualStartMillis, f.StartupVerified)
	return r
}
func (r *admissionRun) load(t *testing.T, f admissionRegistry, initial bool) *registry.Snapshot {
	t.Helper()
	stations := map[string]bool{}
	for _, host := range f.StationHosts {
		stations[host] = true
	}
	policy, err := enrollment.NewPolicy(r.v.Fixture.Audience, f.PublisherKey, stations)
	if err != nil {
		t.Fatal(err)
	}
	var entries []registry.Entry
	for _, file := range f.Files {
		if file.Kind != "regular" || file.Repeat != 1 {
			t.Fatal("unsupported registration registry entry kind/repeat")
		}
		entries = append(entries, registry.Entry{Path: file.Path, Bytes: decodeExpected(t, file.Bytes), Kind: registry.Regular})
	}
	r.store.available = f.PersistAvailable
	// Registration fixtures attest permitted initial authority with their own
	// rollback-state evidence. Empty storage cannot grant that permission.
	// Later publications are reloads even if an earlier load returned no state.
	input := registry.Input{Revision: f.Revision, Entries: entries, Retained: r.store.water.Clone(), FirstUse: initial && f.RollbackStateAvailable, Reconciled: f.RollbackStateAvailable}
	snapshot, water, err := (registry.Loader{Policy: policy, Verifier: admissionTrust{fixture: f, entries: entries}, Store: r.store}).Load(input)
	if err != nil {
		if snapshot != nil || water != nil {
			t.Fatal("refused registry published partial authority")
		}
		if refusal.Is(err, refusal.RegistryUnavailable) {
			return nil // The real loader fences; the Handler decides the refusal.
		}
		t.Fatalf("fixture registry loader: %v", err)
	}
	return snapshot
}
func (r *admissionRun) start(t *testing.T, millis int64, verified bool) {
	t.Helper()
	head := admission.AuditHead{}
	if len(r.audit.lines) > 0 {
		head = admission.AuditHead{Sequence: int64(len(r.audit.lines)), Hash: admissionHash(r.audit.lines[len(r.audit.lines)-1])}
	}
	var err error
	r.core, err = admission.New(admission.Config{Audience: r.v.Fixture.Audience, Clock: r.clock,
		Startup:  admission.Startup{Reading: admission.Reading{UTC: millis / 1000, Healthy: verified}, Ordered: verified},
		Registry: r.snapshot, Signer: r.signer, Audit: r.audit, Head: head, Instance: r.instance,
		Limits: &admission.Limits{PerKey: r.v.Fixture.KeyCapacity, PerName: r.v.Fixture.NameCapacity}})
	if err != nil {
		t.Fatal(err)
	}
	r.handler, err = httpapi.New(r.core)
	if err != nil {
		t.Fatal(err)
	}
}
func (r *admissionRun) transition(t *testing.T, s admissionTransition) {
	t.Helper()
	switch s.Event {
	case "request":
		r.request(t, s.Bytes, s.Now, s.Expected, false)
	case "clock":
		if s.Now < r.clock.reading.UTC {
			r.clock.reading.Faulted = true
		}
		r.clock.reading.UTC, r.clock.reading.Healthy = s.Now, s.Healthy
		if !s.Healthy {
			r.clock.reading.Faulted = true
		}
	case "restart":
		if s.StartupVerified && r.lastAdmission != nil && *r.lastAdmission > s.ActualStartMillis/1000 {
			t.Fatal("verified restart violates fixture's admission/start ordering premise")
		}
		r.clock.reading.UTC, r.clock.reading.Healthy, r.clock.reading.Faulted = s.Now, s.StartupVerified, false
		r.instance[0]++
		r.start(t, s.ActualStartMillis, s.StartupVerified)
	case "signer":
		r.signer.available = s.Available
	default:
		t.Fatalf("unsupported trace event %q", s.Event)
	}
}

func admissionStatus(code string) int {
	switch code {
	case "accept", "issued":
		return 200
	case "endpoint_not_found":
		return 404
	case "method_not_allowed":
		return 405
	case "request_too_large":
		return 413
	case "unsupported_media_type":
		return 415
	case "registration_malformed", "registration_id_mismatch", "name_invalid", "clock_skew":
		return 400
	case "registration_signature_invalid", "signature_high_s", "key_not_enrolled", "key_not_valid_now", "host_revoked", "name_not_permitted", "audience_mismatch", "request_not_yet_valid", "request_expired":
		return 403
	case "nonce_replayed":
		return 409
	case "rate_limited":
		return 429
	case "registry_unavailable", "service_unavailable", "audit_unavailable":
		return 503
	}
	return 0
}
func (r *admissionRun) disagree(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DISAGREEMENT %s spec/registrar.md:%d (plan=%s) %s: code=%v vector=%v", r.v.Row, r.spec.line, r.spec.outcome, what, got, want)
	}
}
func (r *admissionRun) request(t *testing.T, encoded string, now int64, want admissionExpected, main bool) {
	t.Helper()
	f := r.v.Fixture
	r.clock.reading.UTC = now
	raw := decodeExpected(t, encoded)
	initial := r.snapshot
	if main {
		revoke := func() {
			if f.ScheduledRegistry == nil {
				t.Fatal("scheduled revocation lacks registry")
			}
			r.snapshot = r.load(t, *f.ScheduledRegistry, false)
			r.core.Publish(r.snapshot)
			r.revoked = true
		}
		if f.FinalRevoked {
			r.signer.duringSign = revoke
		}
		if f.FinalNow != nil {
			r.signer.duringSign = func() { r.clock.reading.UTC = *f.FinalNow }
		}
		if f.PostAuditRevoked {
			r.audit.duringAck = revoke
		}
		if f.PostAuditGeneration != "" {
			r.audit.duringAck = func() {
				// Published generation B test seed: byte 0x42 repeated 32 times.
				r.signer = &admissionSigner{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)), available: true}
				r.core.Cutover(r.signer)
				r.core.ResumeSigning()
			}
		}
	}
	httpFixture := f.HTTP
	req := httptest.NewRequest(httpFixture.Method, httpFixture.Path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", httpFixture.ContentType)
	if httpFixture.ContentEncoding != "" {
		req.Header.Set("Content-Encoding", httpFixture.ContentEncoding)
	}
	if httpFixture.ContentLengthPresent != nil && !*httpFixture.ContentLengthPresent {
		req.ContentLength = -1
	}
	response := httptest.NewRecorder()
	r.handler.ServeHTTP(response, req)
	if response.Code == http.StatusOK {
		at := now
		r.lastAdmission = &at
	}
	r.disagree(t, "HTTP status", response.Code, admissionStatus(want.Code))
	var expectedBody []byte
	if want.Code == "accept" {
		if want.JWT == nil {
			t.Fatal("positive fixture missing exact JWT")
		}
		expectedBody, _ = json.Marshal(struct {
			JWT string `json:"jwt"`
		}{want.JWT.Compact})
	} else {
		expectedBody, _ = json.Marshal(struct {
			Code    string            `json:"code"`
			Message string            `json:"message"`
			Details map[string]string `json:"details"`
		}{want.Code, "Registration request refused.", map[string]string{}})
	}
	r.disagree(t, "HTTP body (including exact JWT or absence)", response.Body.String(), string(expectedBody))
	r.disagree(t, "response content type", response.Header().Get("Content-Type"), "application/json")
	r.disagree(t, "response cache control", response.Header().Get("Cache-Control"), "no-store")
	if want.Code == "method_not_allowed" {
		r.disagree(t, "Allow", response.Header().Get("Allow"), "POST")
	}
	if r.audit.local {
		// The fixture pins outcomes. §9 requires an extra refusal after a
		// committed issuance whose acknowledgement/final release fails.
		issued := want.Code == "accept" || main && (f.PostAuditRevoked || f.PostAuditGeneration != "" || want.Code == "audit_unavailable" && !f.Audit.RemoteAck)
		if issued {
			r.expectAudit(t, raw, "issued", now, now, initial)
		}
		if want.Code != "accept" {
			r.expectAudit(t, raw, want.Code, r.clock.reading.UTC, 0, r.snapshot)
		}
	}
	r.disagree(t, "audit lines", admissionLineStrings(r.audit.lines), admissionLineStrings(r.wantLines))
	if r.audit.remote {
		r.disagree(t, "exact acknowledged lines", admissionLineStrings(r.audit.acks), admissionLineStrings(r.audit.lines))
	} else {
		r.disagree(t, "no off-host acknowledgements", len(r.audit.acks), 0)
	}
	if main && want.AuditLine != "" {
		if len(r.audit.lines) != 1 {
			t.Error("pinned audit fixture requires exactly one line")
		} else {
			r.disagree(t, "pinned audit line", string(r.audit.lines[0]), string(decodeExpected(t, want.AuditLine)))
			r.disagree(t, "pinned audit hash", admissionHash(r.audit.lines[0]), want.AuditHash)
		}
	}
}

func admissionLineStrings(lines [][]byte) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = string(line)
	}
	return out
}

// Build the audit oracle from verified fixture input, the declared ordered
// refusal stage and §9, never from the returned HTTP body or emitted event.
func (r *admissionRun) expectAudit(t *testing.T, raw []byte, code string, now, jwtIat int64, snapshot *registry.Snapshot) {
	t.Helper()
	var id, key, host, name, revision, iat, exp any
	f := r.v.Fixture.HTTP
	observed := len(raw)
	if observed > 65537 {
		observed = 65537
	}
	if f.Path != "/v1/registration" || f.Method != http.MethodPost {
		observed = 0
	}
	proof, err := registration.Parse(raw)
	early := code == "endpoint_not_found" || code == "method_not_allowed" || code == "request_too_large" || code == "unsupported_media_type"
	if err == nil && !early {
		id, key = proof.ID, "sha256:"+admissionHash([]byte(proof.Key.Encoding()))
		if snapshot != nil {
			revision = snapshot.Revision()
			if rec, _, exists := snapshot.LookupKey(proof.Key.Encoding()); exists {
				host = rec.Host()
				if code != "key_not_valid_now" && code != "host_revoked" && code != "name_invalid" {
					name = proof.Name
				}
				// A late revocation follows name verification and retains it.
				if code == "host_revoked" && (r.v.Fixture.FinalRevoked || r.v.Fixture.PostAuditRevoked) {
					name = proof.Name
				}
			}
		}
	}
	outcome := "refused"
	if code == "issued" {
		outcome, iat, exp = "issued", jwtIat, jwtIat+120
	}
	previous := strings.Repeat("0", 64)
	if len(r.wantLines) > 0 {
		previous = admissionHash(r.wantLines[len(r.wantLines)-1])
	}
	event := map[string]any{"v": int64(1), "seq": int64(len(r.wantLines) + 1), "at": time.Unix(now, 0).UTC().Format("2006-01-02T15:04:05Z"), "instance": base64.RawURLEncoding.EncodeToString(r.instance[:]), "jti": id, "key_id": key, "host": host, "name": name, "outcome": outcome, "code": code, "http_status": int64(admissionStatus(code)), "registry_revision": revision, "jwt_iat": iat, "jwt_exp": exp, "request_bytes": int64(observed), "prev_hash": previous}
	line, err := ccj.Marshal(event, refusal.AuditUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	r.wantLines = append(r.wantLines, append(line, '\n'))
}

// Observation is read-only, after synchronous requests have quiesced. Reflection
// reads primitive private accounting fields because there is no snapshot API;
// it never writes fields, calls unsafe, seeds state or replaces service logic.
// Limiter comparisons project fixture events into the two independent budgets;
// the implementation does not retain an association between their event lists.
func (r *admissionRun) checkAccounting(t *testing.T, noncesWant []admissionNonce, eventsWant []admissionEvent) {
	t.Helper()
	state := reflect.ValueOf(r.core).Elem()
	var gotNonces []admissionNonce
	nonces := state.FieldByName("nonces")
	for _, pair := range nonces.MapKeys() {
		n := pair.FieldByName("nonce")
		raw := make([]byte, n.Len())
		for i := range raw {
			raw[i] = byte(n.Index(i).Uint())
		}
		gotNonces = append(gotNonces, admissionNonce{Key: pair.FieldByName("key").String(), Nonce: base64.RawURLEncoding.EncodeToString(raw), Expires: nonces.MapIndex(pair).Int()})
	}
	sortNonces := func(values []admissionNonce) []admissionNonce {
		out := append([]admissionNonce{}, values...)
		sort.Slice(out, func(i, j int) bool { return out[i].Key+out[i].Nonce < out[j].Key+out[j].Nonce })
		return out
	}
	r.disagree(t, "final nonce cache", sortNonces(gotNonces), sortNonces(noncesWant))
	for _, budget := range []string{"keyEvents", "nameEvents"} {
		got, expected := map[string][]int64{}, map[string][]int64{}
		for _, event := range eventsWant {
			id := event.Key
			if budget == "nameEvents" {
				id = event.Name
			}
			expected[id] = append(expected[id], event.At*int64(time.Second))
		}
		entries := state.FieldByName(budget)
		for _, id := range entries.MapKeys() {
			values := entries.MapIndex(id)
			for i := 0; i < values.Len(); i++ {
				got[id.String()] = append(got[id.String()], values.Index(i).Int())
			}
		}
		r.disagree(t, "final "+budget, got, expected)
	}
}

func (r *admissionRun) checkState(t *testing.T) {
	t.Helper()
	want := r.v.Expected.State
	state := reflect.ValueOf(r.core).Elem()
	r.checkAccounting(t, want.NonceCache, want.LimiterEvents)
	var outcomes []string
	for _, line := range r.audit.lines {
		var event struct{ Code string }
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		outcomes = append(outcomes, event.Code)
	}
	r.disagree(t, "final audit outcomes", append([]string{}, outcomes...), want.AuditOutcomes)
	r.disagree(t, "clock fence", state.FieldByName("clockFenced").Bool(), want.ClockFenced)
	r.disagree(t, "start barrier", state.FieldByName("barrier").Int(), want.StartBarrier)
	r.disagree(t, "signer readiness", r.signer.available && !state.FieldByName("signing").FieldByName("paused").Bool(), want.SignerReady)
	r.disagree(t, "audit readiness", !state.FieldByName("auditFenced").Bool() && r.audit.local && r.audit.remote, want.AuditReady)
	r.disagree(t, "registry readiness", !state.FieldByName("snapshot").IsNil(), want.RegistryReady)
	r.disagree(t, "published snapshot identity", state.FieldByName("snapshot").Pointer(), reflect.ValueOf(r.snapshot).Pointer())
	head := state.FieldByName("head")
	r.disagree(t, "audit head sequence", head.FieldByName("Sequence").Int(), int64(len(r.audit.lines)))
	wantHash := strings.Repeat("0", 64)
	if len(r.audit.lines) > 0 {
		wantHash = admissionHash(r.audit.lines[len(r.audit.lines)-1])
	}
	r.disagree(t, "audit head hash", head.FieldByName("Hash").String(), wantHash)
	generation := state.FieldByName("signing").FieldByName("generation").Uint()
	r.disagree(t, "signing generation", string(rune('A'+generation-1)), want.SigningGeneration)
	r.disagree(t, "scheduled revocation", r.revoked, want.ScheduledRevocationApplied)
	if r.store.water != nil {
		ids := []string{}
		for _, host := range r.store.water.Hosts {
			for _, id := range host.History {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		r.disagree(t, "persisted authority record ids", ids, want.Authority.RecordIDs)
		r.disagree(t, "persisted authority revision", r.store.water.Revision, want.Authority.Revision)
	} else {
		if want.RegistryReady {
			t.Error("ready registry has no persisted authority")
		}
		// With unavailable trust, the fixture's authority descriptor names the
		// configured candidate only. It does not assert successful publication.
		// Check that descriptor, while the nil snapshot/store checks above prove
		// no usable or partially persisted authority was returned by the loader.
		ids := []string{}
		for _, file := range r.v.Fixture.Registry.Files {
			var record struct{ ID string }
			if err := json.Unmarshal(decodeExpected(t, file.Bytes), &record); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, record.ID)
		}
		sort.Strings(ids)
		r.disagree(t, "unavailable configured candidate ids", ids, want.Authority.RecordIDs)
		r.disagree(t, "unavailable configured candidate revision", r.v.Fixture.Registry.Revision, want.Authority.Revision)
	}
}
