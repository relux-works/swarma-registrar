package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/registry"
)

const epoch int64 = 1893456000

// Test seeds are public: each is the argument byte repeated 32 times.
func private(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func public(seed byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(private(seed).Public().(ed25519.PublicKey))
}
func signed(t *testing.T, domain envelope.Domain, body map[string]any, seed byte) []byte {
	t.Helper()
	pre, id, err := envelope.SigningInput(domain, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private(seed), pre))}, domain.Malformed())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func proof(t *testing.T, nonce byte, name, aud string, iat, exp int64) *registration.Body {
	return proofKey(t, 2, nonce, name, aud, iat, exp)
}
func proofKey(t *testing.T, seed, nonce byte, name, aud string, iat, exp int64) *registration.Body {
	t.Helper()
	stamp := func(sec int64) string { return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z") }
	raw := signed(t, envelope.Registration, map[string]any{"type": "registration/1", "key": public(seed), "name": name, "aud": aud, "nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{nonce}, 16)), "iat": stamp(iat), "exp": stamp(exp)}, seed)
	out, err := registration.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type trust struct{}

func (trust) Verify(string, []registry.Entry) error { return nil }
func (trust) Descends(string, string) (bool, error) { return true, nil }

type waterStore struct{}

func (waterStore) Commit(*registry.HighWater, registry.HighWater) error { return nil }
func snapshot(t *testing.T, seed byte, state string, lo, hi int64) *registry.Snapshot {
	t.Helper()
	p, err := enrollment.NewPolicy("example.org", public(1), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	stamp := func(sec int64) string { return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z") }
	raw := signed(t, envelope.Enrollment, map[string]any{"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": state, "keys": []any{map[string]any{"key": public(seed), "not_before": stamp(lo), "not_after": stamp(hi)}}, "names": map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}}}, 1)
	s, _, err := (registry.Loader{ObjectFormat: "sha1", Policy: p, Verifier: trust{}, Store: waterStore{}}).Load(registry.Input{Revision: strings.Repeat("1", 40), FirstUse: true, Entries: []registry.Entry{{Path: "enrollments/a.json", Bytes: raw}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type deadline struct {
	at     time.Duration
	cancel context.CancelFunc
}
type fakeClock struct {
	mu        sync.Mutex
	reading   Reading
	next      int
	deadlines map[int]deadline
}

func (c *fakeClock) Now() Reading { c.mu.Lock(); defer c.mu.Unlock(); return c.reading }
func (c *fakeClock) Deadline(parent context.Context, at time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	c.next++
	id := c.next
	if c.deadlines == nil {
		c.deadlines = map[int]deadline{}
	}
	c.deadlines[id] = deadline{at, cancel}
	expired := c.reading.Monotonic >= at
	c.mu.Unlock()
	if expired {
		cancel()
	}
	return ctx, func() { c.mu.Lock(); delete(c.deadlines, id); c.mu.Unlock(); cancel() }
}
func (c *fakeClock) set(r Reading) {
	c.mu.Lock()
	c.reading = r
	var cancels []context.CancelFunc
	for _, d := range c.deadlines {
		if r.Monotonic >= d.at {
			cancels = append(cancels, d.cancel)
		}
	}
	c.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}
func (c *fakeClock) advance(d time.Duration) {
	r := c.Now()
	r.UTC += int64(d / time.Second)
	r.Monotonic += d
	c.set(r)
}

type fakeSigner struct {
	key              ed25519.PrivateKey
	fail, bad        bool
	hook             func()
	entered, release chan struct{}
}

func (s *fakeSigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }
func (s *fakeSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if s.hook != nil {
		s.hook()
	}
	if s.entered != nil {
		s.entered <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.fail {
		return nil, errors.New("signing failed")
	}
	if s.bad {
		return make([]byte, 64), nil
	}
	return ed25519.Sign(s.key, message), nil
}

type fakeAudit struct {
	mu                            sync.Mutex
	lines, acks                   [][]byte
	localFail, ackFail, probeFail bool
	hook                          func()
	entered, release              chan struct{}
}

func (s *fakeAudit) Append(ctx context.Context, line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.localFail {
		return errors.New("local unavailable")
	}
	var entry map[string]any
	if err := json.Unmarshal(line, &entry); err != nil {
		return err
	}
	if entry["seq"] != float64(len(s.lines)+1) {
		return errors.New("sequence")
	}
	expected := strings.Repeat("0", 64)
	if len(s.lines) > 0 {
		sum := sha256.Sum256(s.lines[len(s.lines)-1])
		expected = hex.EncodeToString(sum[:])
	}
	if entry["prev_hash"] != expected {
		return errors.New("chain")
	}
	s.lines = append(s.lines, bytes.Clone(line))
	return nil
}
func (s *fakeAudit) Acknowledge(ctx context.Context, line []byte) error {
	if s.hook != nil {
		s.hook()
	}
	if s.entered != nil {
		s.entered <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.ackFail {
		return errors.New("remote unavailable")
	}
	s.acks = append(s.acks, bytes.Clone(line))
	return nil
}
func (s *fakeAudit) Probe(ctx context.Context, head AuditHead) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.probeFail {
		return errors.New("still unavailable")
	}
	expected := strings.Repeat("0", 64)
	if len(s.lines) > 0 {
		sum := sha256.Sum256(s.lines[len(s.lines)-1])
		expected = hex.EncodeToString(sum[:])
	}
	if head.Sequence != int64(len(s.lines)) || head.Hash != expected {
		return errors.New("head")
	}
	return nil
}
func (s *fakeAudit) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, len(s.lines))
	for i, line := range s.lines {
		if err := json.Unmarshal(line, &out[i]); err != nil {
			panic(err)
		}
	}
	return out
}

type fixture struct {
	a      *Admitter
	clock  *fakeClock
	signer *fakeSigner
	audit  *fakeAudit
	cfg    Config
}

func setup(t *testing.T) *fixture {
	t.Helper()
	clock := &fakeClock{reading: Reading{UTC: epoch + 100, Monotonic: 100 * time.Second, Healthy: true}}
	signer := &fakeSigner{key: private(9)}
	audit := &fakeAudit{}
	cfg := Config{Audience: "example.org", Clock: clock, Startup: Startup{Reading: Reading{UTC: epoch, Healthy: true}, Ordered: true}, Registry: snapshot(t, 2, "active", epoch-100, epoch+10000), Signer: signer, Audit: audit, Instance: [16]byte{1}}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{a, clock, signer, audit, cfg}
}
func valid(t *testing.T, nonce byte) *registration.Body {
	return proof(t, nonce, "host-a_project_role", "example.org", epoch+100, epoch+120)
}
func rejected(t *testing.T, a *Admitter, p *registration.Body, code refusal.Code) *Error {
	t.Helper()
	token, err := a.Admit(context.Background(), Request{Proof: p, Bytes: 999999})
	var typed *Error
	if token != "" || !errors.As(err, &typed) || typed.Code != code || !refusal.Is(err, code) {
		t.Fatalf("token=%t error=%v expected=%s", token != "", err, code)
	}
	return typed
}
func issued(t *testing.T, a *Admitter, p *registration.Body) string {
	t.Helper()
	token, err := a.Admit(context.Background(), Request{Proof: p})
	if err != nil || token == "" {
		t.Fatalf("positive control: %v", err)
	}
	return token
}

// Each achievable adjacent pair preserves the earlier verdict; row 21's local
// audit failure overrides row 20 as explicitly required. Rows 16/17 cannot
// co-fail for a verified exp>iat proof; their boundaries are tested separately.
func TestAdjacentChecks(t *testing.T) {
	cases := []struct {
		name string
		code refusal.Code
		edit func(*fixture, *registration.Body) *registration.Body
	}{
		{"8 before 9", refusal.RegistryUnavailable, func(f *fixture, p *registration.Body) *registration.Body { f.a.Publish(nil); return p }},
		{"9 before 10", refusal.KeyNotEnrolled, func(f *fixture, p *registration.Body) *registration.Body {
			f.a.Publish(snapshot(t, 3, "active", epoch-100, epoch))
			return p
		}},
		{"10 before 11", refusal.KeyNotValidNow, func(f *fixture, p *registration.Body) *registration.Body {
			f.a.Publish(snapshot(t, 2, "revoked", epoch-100, epoch))
			return p
		}},
		{"11 before 12", refusal.HostRevoked, func(f *fixture, p *registration.Body) *registration.Body {
			f.a.Publish(snapshot(t, 2, "revoked", epoch-100, epoch+10000))
			return proof(t, 1, "Upper", "example.org", epoch+100, epoch+120)
		}},
		{"12 before 13", refusal.NameInvalid, func(f *fixture, p *registration.Body) *registration.Body {
			return proof(t, 1, "host-b_project_role!", "example.org", epoch+100, epoch+120)
		}},
		{"13 before 14", refusal.NameNotPermitted, func(f *fixture, p *registration.Body) *registration.Body {
			return proof(t, 1, "host-b_project_role", "other.example", epoch+100, epoch+120)
		}},
		{"14 before 15", refusal.AudienceMismatch, func(f *fixture, p *registration.Body) *registration.Body {
			return proof(t, 1, "host-a_project_role", "other.example", epoch+30, epoch+120)
		}},
		{"15 before 16", refusal.ClockSkew, func(f *fixture, p *registration.Body) *registration.Body {
			r := f.clock.Now()
			r.Healthy = false
			f.clock.set(r)
			return proof(t, 1, "host-a_project_role", "example.org", epoch+131, epoch+150)
		}},
		{"17 before 18", refusal.RequestExpired, func(f *fixture, p *registration.Body) *registration.Body {
			for i := byte(2); i < 5; i++ {
				issued(t, f.a, valid(t, i))
			}
			f.clock.advance(50 * time.Second)
			return p
		}},
		{"18 before 19", refusal.RateLimited, func(f *fixture, p *registration.Body) *registration.Body {
			for i := byte(1); i < 4; i++ {
				issued(t, f.a, valid(t, i))
			}
			return p
		}},
		{"19 before 20", refusal.NonceReplayed, func(f *fixture, p *registration.Body) *registration.Body {
			issued(t, f.a, p)
			f.a.PauseSigning()
			return p
		}},
		{"20 before optional refusal ack", refusal.ServiceUnavailable, func(f *fixture, p *registration.Body) *registration.Body {
			f.a.PauseSigning()
			f.audit.ackFail = true
			return p
		}},
		{"audit terminal override", refusal.AuditUnavailable, func(f *fixture, p *registration.Body) *registration.Body {
			f.a.PauseSigning()
			f.audit.localFail = true
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			p := tc.edit(f, valid(t, 1))
			rejected(t, f.a, p, tc.code)
			g := setup(t)
			issued(t, g.a, valid(t, 1))
		})
	}
}

// Skew/expiry/window edges and the fixed +31 barrier obey strict whole-second
// bounds. Clock recovery never clears a process fence; only a healthy restart can.
func TestClockEdgesAndRestart(t *testing.T) {
	for _, tc := range []struct {
		name          string
		iat, exp, now int64
		code          refusal.Code
	}{
		{"barrier below", 30, 120, 100, refusal.ClockSkew}, {"future", 131, 150, 100, refusal.RequestNotYetValid}, {"expired", 100, 120, 150, refusal.RequestExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			r := f.clock.Now()
			r.UTC = epoch + tc.now
			f.clock.set(r)
			rejected(t, f.a, proof(t, 1, "host-a_project_role", "example.org", epoch+tc.iat, epoch+tc.exp), tc.code)
			g := setup(t)
			issued(t, g.a, valid(t, 1))
		})
	}
	for _, tc := range []struct{ iat, exp, now int64 }{{31, 120, 100}, {130, 150, 100}, {100, 120, 149}} {
		f := setup(t)
		r := f.clock.Now()
		r.UTC = epoch + tc.now
		f.clock.set(r)
		issued(t, f.a, proof(t, 1, "host-a_project_role", "example.org", epoch+tc.iat, epoch+tc.exp))
	}
	for _, kind := range []string{"unhealthy startup", "unordered startup", "sync loss", "backwards UTC", "backwards monotonic", "latched fault"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			if kind == "unhealthy startup" || kind == "unordered startup" {
				cfg := f.cfg
				if kind == "unhealthy startup" {
					cfg.Startup.Reading.Healthy = false
				} else {
					cfg.Startup.Ordered = false
				}
				var err error
				f.a, err = New(cfg)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				r := f.clock.Now()
				switch kind {
				case "sync loss":
					r.Healthy = false
				case "backwards UTC":
					r.UTC = epoch - 1
				case "backwards monotonic":
					r.Monotonic = -1
				case "latched fault":
					r.Faulted = true
				}
				f.clock.set(r)
			}
			rejected(t, f.a, valid(t, 1), refusal.ClockSkew)
			f.clock.set(Reading{UTC: epoch + 100, Monotonic: 200 * time.Second, Healthy: true})
			rejected(t, f.a, valid(t, 1), refusal.ClockSkew)
			if f.a.Ready() {
				t.Fatal("fence reopened")
			}
			g := setup(t)
			issued(t, g.a, valid(t, 1))
		})
	}
	f := setup(t)
	old := proof(t, 1, "host-a_project_role", "example.org", epoch+130, epoch+150)
	issued(t, f.a, old)
	cfg := f.cfg
	cfg.Startup = Startup{Reading: f.clock.Now(), Ordered: true}
	cfg.Audit = f.audit
	cfg.Head = f.a.head
	cfg.Instance = [16]byte{2}
	restart, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rejected(t, restart, old, refusal.ClockSkew)
	f.clock.advance(31 * time.Second)
	rejected(t, restart, old, refusal.ClockSkew)
	issued(t, restart, proof(t, 2, "host-a_project_role", "example.org", epoch+131, epoch+150))
}

// Nonces are consumed after reservation even on later failure; concurrent copies
// produce one token. This test uses real verified proofs, not fabricated bodies.
func TestNonceConsumptionAndConcurrency(t *testing.T) {
	f := setup(t)
	p := valid(t, 1)
	f.signer.fail = true
	rejected(t, f.a, p, refusal.ServiceUnavailable)
	f.signer.fail = false
	rejected(t, f.a, p, refusal.NonceReplayed)
	issued(t, f.a, valid(t, 2))
	g := setup(t)
	const count = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	issuedCount := 0
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _ := g.a.Admit(context.Background(), Request{Proof: p})
			if token != "" {
				mu.Lock()
				issuedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if issuedCount != 1 {
		t.Fatal(issuedCount)
	}
}

// Budgets use monotonic sliding windows, atomic two-budget debit, and exact
// minimum ceil retry delay. Earlier failures debit nothing; replay still counts.
func TestBudgetBoundaries(t *testing.T) {
	f := setup(t)
	for n := byte(1); n <= 3; n++ {
		issued(t, f.a, valid(t, n))
	}
	err := rejected(t, f.a, valid(t, 4), refusal.RateLimited)
	if err.RetryAfter != 60 {
		t.Fatal(err)
	}
	f.clock.advance(60*time.Second - time.Nanosecond)
	err = rejected(t, f.a, proof(t, 4, "host-a_project_role", "example.org", epoch+159, epoch+180), refusal.RateLimited)
	if err.RetryAfter != 1 {
		t.Fatal(err)
	}
	f.clock.advance(time.Nanosecond)
	issued(t, f.a, proof(t, 4, "host-a_project_role", "example.org", epoch+159, epoch+180))
	for _, limits := range []Limits{{0, 1}, {1, 0}, {11, 1}, {1, 4}, {-1, 1}} {
		g := setup(t)
		cfg := g.cfg
		cfg.Limits = &limits
		if _, err := New(cfg); err == nil {
			t.Fatal("invalid capacities")
		}
	}
	g := setup(t)
	cfg := g.cfg
	cfg.Limits = &Limits{1, 1}
	a, newErr := New(cfg)
	if newErr != nil {
		t.Fatal(newErr)
	}
	issued(t, a, valid(t, 1))
	rejected(t, a, valid(t, 2), refusal.RateLimited)
}

// JWT contents and chained audit bytes obey the exact schema; no bearer secret,
// signature, raw nonce or body is recorded, and the signer cannot choose claims.
func TestJWTAndAudit(t *testing.T) {
	f := setup(t)
	p := proof(t, 7, "host-a_project_role", "example.org", epoch+70, epoch+110)
	token := issued(t, f.a, p)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("segments")
	}
	header, _ := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	payload, _ := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	signature, _ := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if string(header) != `{"alg":"EdDSA","typ":"JWT"}` || !ed25519.Verify(f.signer.PublicKey(), []byte(parts[0]+"."+parts[1]), signature) {
		t.Fatal("JWS")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"iss": "swarma-registrar", "aud": []any{"example.org"}, "sub": p.Name, "iat": float64(epoch + 100), "nbf": float64(epoch + 100), "exp": float64(epoch + 220), "jti": p.ID}
	if !reflect.DeepEqual(claims, want) {
		t.Fatal(claims)
	}
	event := f.audit.events()[0]
	if len(event) != 16 || event["code"] != "issued" || event["jwt_exp"] != float64(epoch+220) || event["name"] != p.Name {
		t.Fatal(event)
	}
	f.signer.fail = true
	rejected(t, f.a, valid(t, 8), refusal.ServiceUnavailable)
	events := f.audit.events()
	if events[1]["request_bytes"] != float64(65537) || events[1]["jwt_iat"] != nil {
		t.Fatal(events[1])
	}
	for _, line := range f.audit.lines {
		if bytes.Contains(line, []byte(token)) || bytes.Contains(line, []byte(base64.RawURLEncoding.EncodeToString(p.Nonce))) || line[len(line)-1] != '\n' {
			t.Fatal("audit secret/line")
		}
	}
	if len(f.audit.acks) != 2 {
		t.Fatal("acknowledgements")
	}
}

// Post-sign and post-ack changes cancel pending authority without refund or
// implicit re-sign. Audit I/O cannot hold the publication/cutover mutex.
func TestFinalRevalidationAndCutover(t *testing.T) {
	for _, phase := range []string{"sign", "audit"} {
		for _, change := range []string{"registry", "generation", "pause", "clock"} {
			t.Run(phase+"/"+change, func(t *testing.T) {
				f := setup(t)
				code := refusal.ServiceUnavailable
				hook := func() {
					switch change {
					case "registry":
						f.a.Publish(snapshot(t, 2, "revoked", epoch-100, epoch+10000))
					case "generation":
						f.a.Cutover(&fakeSigner{key: private(10)})
						f.a.ResumeSigning()
					case "pause":
						f.a.PauseSigning()
					case "clock":
						r := f.clock.Now()
						r.Healthy = false
						f.clock.set(r)
					}
				}
				if change == "registry" {
					code = refusal.HostRevoked
				}
				if change == "clock" {
					code = refusal.ClockSkew
				}
				if phase == "sign" {
					f.signer.hook = hook
				} else {
					f.audit.hook = hook
				}
				rejected(t, f.a, valid(t, 1), code)
				f.signer.hook = nil
				f.audit.hook = nil
				events := f.audit.events()
				expected := 1
				if phase == "audit" {
					expected = 2
				}
				if len(events) != expected || events[len(events)-1]["code"] != string(code) {
					t.Fatal(events)
				}
				if len(f.a.nonces) != 1 {
					t.Fatal("reservation refunded")
				}
				g := setup(t)
				issued(t, g.a, valid(t, 1))
			})
		}
	}
}

// Local failure overrides refusals and fences readiness; off-host failure permits
// refusal spooling only. Recovery probes do not reset nonce or limiter state.
func TestAuditFailuresAndRecovery(t *testing.T) {
	f := setup(t)
	f.audit.ackFail = true
	rejected(t, f.a, valid(t, 1), refusal.AuditUnavailable)
	if len(f.audit.events()) != 2 {
		t.Fatal("missing failure record")
	}
	f.audit.ackFail = false
	rejected(t, f.a, valid(t, 1), refusal.NonceReplayed)
	issued(t, f.a, valid(t, 2))
	g := setup(t)
	g.audit.localFail = true
	rejected(t, g.a, proof(t, 1, "Upper", "example.org", epoch+100, epoch+120), refusal.AuditUnavailable)
	if g.a.Ready() || len(g.audit.events()) != 0 {
		t.Fatal("false readiness/audit")
	}
	g.audit.localFail = false
	g.audit.probeFail = true
	if err := g.a.RecoverAudit(context.Background()); err == nil {
		t.Fatal("bad probe")
	}
	g.audit.probeFail = false
	if err := g.a.RecoverAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	issued(t, g.a, valid(t, 2))
	if err := g.a.Refuse(context.Background(), refusal.RegistrationIDMismatch, 100); !refusal.Is(err, refusal.RegistrationIDMismatch) {
		t.Fatal(err)
	}
	e := g.audit.events()
	last := e[len(e)-1]
	for _, field := range []string{"jti", "key_id", "host", "name"} {
		if last[field] != nil {
			t.Fatal("unverified identity", last)
		}
	}
}

// Injected monotonic deadlines bound blocked signing/acknowledgement without a
// real clock source; timeouts release no token and retain reservations.
func TestDeadline(t *testing.T) {
	for _, stage := range []string{"sign", "audit"} {
		t.Run(stage, func(t *testing.T) {
			f := setup(t)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			if stage == "sign" {
				f.signer.entered = entered
				f.signer.release = release
			} else {
				f.audit.entered = entered
				f.audit.release = release
			}
			result := make(chan error, 1)
			go func() {
				token, err := f.a.Admit(context.Background(), Request{Proof: valid(t, 1)})
				if token != "" {
					result <- fmt.Errorf("released timed-out JWT")
					return
				}
				result <- err
			}()
			<-entered
			f.clock.advance(5 * time.Second)
			err := <-result
			if !refusal.Is(err, refusal.AuditUnavailable) {
				t.Fatal(err)
			}
			if len(f.a.nonces) != 1 {
				t.Fatal("reservation refunded")
			}
			g := setup(t)
			issued(t, g.a, valid(t, 1))
		})
	}
}
