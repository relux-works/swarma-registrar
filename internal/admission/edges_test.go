package admission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/registry"
)

func withKeys(t *testing.T, explicit []any, seeds ...byte) *registry.Snapshot {
	t.Helper()
	p, err := enrollment.NewPolicy("example.org", public(1), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	list := make([]any, len(seeds))
	for i, seed := range seeds {
		list[i] = map[string]any{"key": public(seed), "not_before": "2029-01-01T00:00:00Z", "not_after": "2031-01-01T00:00:00Z"}
	}
	raw := signed(t, envelope.Enrollment, map[string]any{"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active", "keys": list, "names": map[string]any{"prefix": "host-a_", "explicit": explicit}}, 1)
	s, _, err := (registry.Loader{Policy: p, Verifier: trust{}, Store: waterStore{}}).Load(registry.Input{Revision: strings.Repeat("2", 40), FirstUse: true, Entries: []registry.Entry{{Path: "enrollments/a.json", Bytes: raw}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A retained pair rejects changed IDs and scopes by key, does not extend on a
// replay, and cannot be reclaimed before the exact original exp+30 boundary.
func TestNonceScopeAndRetention(t *testing.T) {
	f := setup(t)
	f.a.Publish(withKeys(t, []any{}, 2, 3))
	issued(t, f.a, valid(t, 1))
	changed := proof(t, 1, "host-a_other_role", "example.org", epoch+100, epoch+120)
	rejected(t, f.a, changed, refusal.NonceReplayed)
	issued(t, f.a, proofKey(t, 3, 1, "host-a_another_role", "example.org", epoch+100, epoch+120))
	if len(f.a.nonces) != 2 {
		t.Fatal("nonce key scope")
	}
	f.clock.advance(49 * time.Second)
	rejected(t, f.a, proof(t, 1, "host-a_before_role", "example.org", epoch+149, epoch+160), refusal.NonceReplayed)
	if len(f.a.nonces) != 2 {
		t.Fatal("early reclamation")
	}
	f.clock.advance(time.Second)
	issued(t, f.a, proof(t, 1, "host-a_after_role", "example.org", epoch+150, epoch+160))
	if len(f.a.nonces) != 1 {
		t.Fatal("retention boundary")
	}
	for _, expiry := range f.a.nonces {
		if expiry != epoch+190 {
			t.Fatal("new reservation")
		}
	}
}

// Limits charge both budgets or neither, share a name across keys, and depend
// only on monotonic elapsed time, not a forward UTC step.
func TestAtomicBudgetsAndClockDomain(t *testing.T) {
	f := setup(t)
	f.a.Publish(withKeys(t, []any{}, 2, 3))
	for i, seed := range []byte{2, 3, 2} {
		issued(t, f.a, proofKey(t, seed, byte(i+1), "host-a_project_role", "example.org", epoch+100, epoch+120))
	}
	before := len(f.a.keyEvents[public(3)])
	rejected(t, f.a, proofKey(t, 3, 9, "host-a_project_role", "example.org", epoch+100, epoch+120), refusal.RateLimited)
	if len(f.a.keyEvents[public(3)]) != before || len(f.a.nonces) != 3 {
		t.Fatal("partial charge/reservation")
	}
	r := f.clock.Now()
	r.UTC += 100
	r.Monotonic += time.Second
	f.clock.set(r)
	e := rejected(t, f.a, proof(t, 9, "host-a_project_role", "example.org", epoch+200, epoch+220), refusal.RateLimited)
	if e.RetryAfter != 59 {
		t.Fatal(e)
	}
	f.clock.advance(59 * time.Second)
	issued(t, f.a, proof(t, 9, "host-a_project_role", "example.org", epoch+259, epoch+279))
	g := setup(t)
	for i := byte(1); i <= 10; i++ {
		issued(t, g.a, proof(t, i, "host-a_project_r"+string(rune('a'+i)), "example.org", epoch+100, epoch+120))
	}
	rejected(t, g.a, proof(t, 11, "host-a_project_extra", "example.org", epoch+100, epoch+120), refusal.RateLimited)
	if len(g.a.nameEvents) != 10 || len(g.a.keyEvents[public(2)]) != 10 || len(g.a.nonces) != 10 {
		t.Fatal("key capacity/partial name charge")
	}
	h := setup(t)
	rejected(t, h.a, proof(t, 1, "Upper", "example.org", epoch+100, epoch+120), refusal.NameInvalid)
	if len(h.a.keyEvents) != 0 || len(h.a.nameEvents) != 0 || len(h.a.nonces) != 0 {
		t.Fatal("unauthenticated stage charged")
	}
	issued(t, h.a, valid(t, 1))
}

// Every release check uses the live snapshot/time, and final refusal preserves
// the previously committed issued event without returning its JWT.
func TestPostAckAuthorityAndTime(t *testing.T) {
	for _, kind := range []string{"registry fence", "key removed", "window ended", "name removed", "proof expired", "same key restored"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			p := valid(t, 1)
			code := refusal.RegistryUnavailable
			switch kind {
			case "key removed":
				code = refusal.KeyNotEnrolled
			case "window ended":
				f.a.Publish(snapshot(t, 2, "active", epoch-100, epoch+101))
				code = refusal.KeyNotValidNow
			case "name removed":
				p = proof(t, 1, "legacy.dev", "example.org", epoch+100, epoch+120)
				code = refusal.NameNotPermitted
			case "proof expired":
				p = proof(t, 1, "host-a_project_role", "example.org", epoch+70, epoch+71)
				code = refusal.RequestExpired
			case "same key restored":
				code = refusal.ServiceUnavailable
			}
			f.audit.hook = func() {
				switch kind {
				case "registry fence":
					f.a.Publish(nil)
				case "key removed":
					f.a.Publish(snapshot(t, 3, "active", epoch-100, epoch+10000))
				case "window ended", "proof expired":
					f.clock.advance(time.Second)
				case "name removed":
					f.a.Publish(withKeys(t, []any{}, 2))
				case "same key restored":
					f.a.Cutover(&fakeSigner{key: private(10)})
					f.a.ResumeSigning()
					f.a.Cutover(f.signer)
					f.a.ResumeSigning()
				}
			}
			// Acknowledgement hooks run for the issued and refusal line; apply once only.
			hook := f.audit.hook
			called := false
			f.audit.hook = func() {
				if !called {
					called = true
					hook()
				}
			}
			rejected(t, f.a, p, code)
			events := f.audit.events()
			if len(events) != 2 || events[0]["outcome"] != "issued" || events[1]["code"] != string(code) || len(f.a.nonces) != 1 {
				t.Fatal(events)
			}
			g := setup(t)
			issued(t, g.a, valid(t, 1))
		})
	}
}

// Audit lines have exactly the specified fields, canonical LF framing, an
// independent SHA-256 chain and stage-appropriate null identities.
func TestAuditLineContract(t *testing.T) {
	f := setup(t)
	rejected(t, f.a, proof(t, 1, "Upper", "example.org", epoch+100, epoch+120), refusal.NameInvalid)
	issued(t, f.a, valid(t, 2))
	fields := strings.Fields("v seq at instance jti key_id host name outcome code http_status registry_revision jwt_iat jwt_exp request_bytes prev_hash")
	previous := strings.Repeat("0", 64)
	for i, line := range f.audit.lines {
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if len(event) != len(fields) {
			t.Fatal(event)
		}
		for _, field := range fields {
			if _, ok := event[field]; !ok {
				t.Fatal(field)
			}
		}
		if event["seq"] != float64(i+1) || event["prev_hash"] != previous || event["instance"] != base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
			t.Fatal(event)
		}
		parsed, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		// For these ASCII, integer-only audit fixtures, encoding/json provides
		// an independent canonical-byte oracle rather than reusing the writer.
		if !bytes.Equal(append(parsed, '\n'), line) {
			t.Fatal("noncanonical audit bytes")
		}
		sum := sha256.Sum256(line)
		previous = hex.EncodeToString(sum[:])
		if line[len(line)-1] != '\n' {
			t.Fatal("framing")
		}
	}
	events := f.audit.events()
	if events[0]["name"] != nil || events[0]["host"] != "host-a" || events[0]["jwt_iat"] != nil || events[0]["http_status"] != float64(400) {
		t.Fatal(events[0])
	}
	key := sha256.Sum256([]byte(public(2)))
	if events[0]["key_id"] != "sha256:"+hex.EncodeToString(key[:]) {
		t.Fatal("key hash")
	}
	if err := f.a.Refuse(context.Background(), refusal.Code("untrusted detail"), 1); !refusal.Is(err, refusal.ServiceUnavailable) {
		t.Fatal(err)
	}
	if bytes.Contains(f.audit.lines[2], []byte("untrusted detail")) {
		t.Fatal("exception leaked")
	}
}

type corruptSigner struct {
	key    ed25519.PrivateKey
	mutate bool
}

func (s corruptSigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }
func (s corruptSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	if s.mutate {
		message[0] ^= 1
	}
	return ed25519.Sign(s.key, message), nil
}

// A signer cannot mutate the JWS input through its callback or substitute an
// invalid signature. Copying a verified proof also isolates later caller edits.
func TestSigningAndProofIsolation(t *testing.T) {
	for _, kind := range []string{"bad signature", "input mutation", "missing signer"} {
		f := setup(t)
		switch kind {
		case "bad signature":
			f.signer.bad = true
		case "input mutation":
			f.a.Cutover(corruptSigner{private(9), true})
			f.a.ResumeSigning()
		case "missing signer":
			f.a.Cutover(nil)
			f.a.ResumeSigning()
		}
		rejected(t, f.a, valid(t, 1), refusal.ServiceUnavailable)
		if len(f.a.nonces) != 1 {
			t.Fatal("refund")
		}
		g := setup(t)
		issued(t, g.a, valid(t, 1))
	}
	f := setup(t)
	p := valid(t, 1)
	originalName := p.Name
	originalID := p.ID
	f.signer.hook = func() { p.Name = "Upper"; p.ID = "changed"; p.Key = nil; clear(p.Nonce) }
	token := issued(t, f.a, p)
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	var claims map[string]any
	json.Unmarshal(raw, &claims)
	if claims["sub"] != originalName || claims["jti"] != originalID {
		t.Fatal("proof mutation")
	}
}

// Later failures retain exactly one debit per budget and the consumed pair;
// retries debit again at row 18 before replay refusal, and a fresh nonce works.
func TestFailureAccounting(t *testing.T) {
	for _, stage := range []string{"sign", "audit", "pause"} {
		t.Run(stage, func(t *testing.T) {
			f := setup(t)
			code := refusal.ServiceUnavailable
			switch stage {
			case "sign":
				f.signer.fail = true
			case "audit":
				f.audit.ackFail = true
				code = refusal.AuditUnavailable
			case "pause":
				f.signer.hook = f.a.PauseSigning
			}
			rejected(t, f.a, valid(t, 1), code)
			if len(f.a.keyEvents[public(2)]) != 1 || len(f.a.nameEvents["host-a_project_role"]) != 1 || len(f.a.nonces) != 1 {
				t.Fatal("failure refunded accounting")
			}
			f.signer.fail = false
			f.audit.ackFail = false
			f.signer.hook = nil
			f.a.ResumeSigning()
			rejected(t, f.a, valid(t, 1), refusal.NonceReplayed)
			if len(f.a.keyEvents[public(2)]) != 2 || len(f.a.nameEvents["host-a_project_role"]) != 2 || len(f.a.nonces) != 1 {
				t.Fatal("retry did not charge exactly once")
			}
			issued(t, f.a, valid(t, 2))
		})
	}
}

// Startup/configuration failures never create authority; limits/configuration
// values are copied and local recovery cannot clear a permanent clock fence.
func TestConfigurationAndRecoveryBounds(t *testing.T) {
	for _, kind := range []string{"no clock", "no audit", "empty audience", "negative deadline", "bad head", "bad start"} {
		f := setup(t)
		cfg := f.cfg
		switch kind {
		case "no clock":
			cfg.Clock = nil
		case "no audit":
			cfg.Audit = nil
		case "empty audience":
			cfg.Audience = ""
		case "negative deadline":
			cfg.Timeout = -1
		case "bad head":
			cfg.Head = AuditHead{Sequence: 1, Hash: "bad"}
		case "bad start":
			cfg.Startup.Reading.Monotonic = -1
		}
		if _, err := New(cfg); err == nil {
			t.Fatal(kind)
		}
		g := setup(t)
		issued(t, g.a, valid(t, 1))
	}
	f := setup(t)
	r := f.clock.Now()
	r.Healthy = false
	f.clock.set(r)
	if f.a.Ready() {
		t.Fatal("unhealthy readiness")
	}
	r.Healthy = true
	f.clock.set(r)
	if err := f.a.RecoverAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	rejected(t, f.a, valid(t, 1), refusal.ClockSkew)
	g := setup(t)
	limits := Limits{1, 1}
	cfg := g.cfg
	cfg.Limits = &limits
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	limits = Limits{10, 3}
	issued(t, a, valid(t, 1))
	rejected(t, a, valid(t, 2), refusal.RateLimited)
}

// A retained nonce is a 409 conflict in the audit as well as a typed replay
// refusal; a new nonce under the same authority remains admissible.
func TestNonceReplayAuditStatus(t *testing.T) {
	f := setup(t)
	issued(t, f.a, valid(t, 1))
	rejected(t, f.a, valid(t, 1), refusal.NonceReplayed)
	events := f.audit.events()
	if events[1]["http_status"] != float64(409) {
		t.Fatalf("replay audit status = %v, want 409", events[1]["http_status"])
	}
	issued(t, f.a, valid(t, 2))
}

// Both proof iat and admission now must lie inside the current half-open key
// interval. A proof at the lower endpoint passes; either endpoint exclusion fails.
func TestKeyWindowBothInstants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lo, hi int64
		iat    int64
	}{
		{"iat before lower", 90, 200, 89},
		{"iat at upper", 0, 101, 101},
		{"now before lower", 101, 200, 101},
		{"now at upper", 0, 100, 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			f.a.Publish(snapshot(t, 2, "active", epoch+tc.lo, epoch+tc.hi))
			rejected(t, f.a, proof(t, 1, "host-a_project_role", "example.org", epoch+tc.iat, epoch+tc.iat+20), refusal.KeyNotValidNow)
			g := setup(t)
			g.a.Publish(snapshot(t, 2, "active", epoch+90, epoch+101))
			issued(t, g.a, proof(t, 1, "host-a_project_role", "example.org", epoch+90, epoch+110))
		})
	}
}
