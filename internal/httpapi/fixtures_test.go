package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/registry"
)

const testEpoch int64 = 1893456000

// Every signing key is derived from public, fixed test material only.
func testPrivate(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func testPublic(seed byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(testPrivate(seed).Public().(ed25519.PublicKey))
}
func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := ccj.Marshal(value, refusal.RegistrationMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func signed(t *testing.T, domain envelope.Domain, body map[string]any, seed byte) []byte {
	t.Helper()
	pre, id, err := envelope.SigningInput(domain, body)
	if err != nil {
		t.Fatal(err)
	}
	return marshal(t, map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(testPrivate(seed), pre))})
}
func proofBody(key string, nonce byte) map[string]any {
	return map[string]any{"type": "registration/1", "key": key, "name": "host-a_project_role", "aud": "example.org", "nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{nonce}, 16)), "iat": "2030-01-01T00:01:40Z", "exp": "2030-01-01T00:02:00Z"}
}
func validProof(t *testing.T, nonce byte) []byte {
	return signed(t, envelope.Registration, proofBody(testPublic(2), nonce), 2)
}
func editEnvelope(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var e map[string]any
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	edit(e)
	return marshal(t, e)
}

// P-256 scalar and nonce are published deterministic seeds. The raw signature
// is normalized only while constructing valid fixtures, never by the handler.
func p256Proof(t *testing.T, high, badRange, badEquation bool) ([]byte, string) {
	t.Helper()
	c := elliptic.P256()
	n := c.Params().N
	scalar := func(text string) *big.Int {
		sum := sha256.Sum256([]byte(text))
		return new(big.Int).Add(new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), new(big.Int).Sub(n, big.NewInt(1))), big.NewInt(1))
	}
	d := scalar("public HTTP P-256 private seed")
	k := scalar("public HTTP P-256 nonce seed")
	x, y := c.ScalarBaseMult(d.Bytes())
	key := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(c, x, y))
	pre, id, err := envelope.SigningInput(envelope.Registration, proofBody(key, 1))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pre)
	rx, _ := c.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Mod(rx, n)
	s := new(big.Int).Mul(r, d)
	s.Add(s, new(big.Int).SetBytes(digest[:]))
	s.Mul(s, new(big.Int).ModInverse(k, n))
	s.Mod(s, n)
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	if high {
		s.Sub(n, s)
	}
	if badEquation {
		r.Add(r, big.NewInt(1))
		if r.Cmp(n) >= 0 {
			r.SetInt64(1)
		}
	}
	if badRange {
		r.SetInt64(0)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return marshal(t, map[string]any{"body": proofBody(key, 1), "id": id, "sig": base64.RawURLEncoding.EncodeToString(sig)}), key
}

type clockFixture struct{ healthy bool }

func (c *clockFixture) Now() admission.Reading {
	return admission.Reading{UTC: testEpoch + 100, Monotonic: 100 * time.Second, Healthy: c.healthy}
}

// These fixed-time HTTP fixtures do not advance the clock or exercise watchdogs;
// admission's own deadline tests cover cancellation. Parent cancellation is kept.
func (*clockFixture) Deadline(ctx context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

type signerFixture struct{ fail bool }

func (*signerFixture) PublicKey() ed25519.PublicKey {
	return testPrivate(9).Public().(ed25519.PublicKey)
}
func (s *signerFixture) Sign(ctx context.Context, b []byte) ([]byte, error) {
	if s.fail {
		return nil, errors.New("synthetic signing failure")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return ed25519.Sign(testPrivate(9), b), nil
}

type auditFixture struct {
	lines, acks   [][]byte
	fail, ackFail bool
}

func (a *auditFixture) Append(ctx context.Context, line []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a.fail {
		return errors.New("synthetic local failure")
	}
	var e map[string]any
	if err := json.Unmarshal(line, &e); err != nil {
		return err
	}
	prev := strings.Repeat("0", 64)
	if len(a.lines) > 0 {
		sum := sha256.Sum256(a.lines[len(a.lines)-1])
		prev = hex.EncodeToString(sum[:])
	}
	if e["seq"] != float64(len(a.lines)+1) || e["prev_hash"] != prev {
		return errors.New("invalid audit chain")
	}
	a.lines = append(a.lines, bytes.Clone(line))
	return nil
}
func (a *auditFixture) Acknowledge(ctx context.Context, line []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a.ackFail {
		return errors.New("synthetic off-host failure")
	}
	a.acks = append(a.acks, bytes.Clone(line))
	return nil
}
func (*auditFixture) Probe(context.Context, admission.AuditHead) error { return nil }
func (a *auditFixture) events(t *testing.T) []map[string]any {
	t.Helper()
	events := make([]map[string]any, len(a.lines))
	for i, line := range a.lines {
		if err := json.Unmarshal(line, &events[i]); err != nil {
			t.Fatal(err)
		}
	}
	return events
}

type verifierFixture struct{}

func (verifierFixture) Verify(string, []registry.Entry) error { return nil }
func (verifierFixture) Descends(string, string) (bool, error) { return true, nil }

type storeFixture struct{}

func (storeFixture) Commit(*registry.HighWater, registry.HighWater) error { return nil }
func snapshotFixture(t *testing.T, key, state string) *registry.Snapshot {
	t.Helper()
	policy, err := enrollment.NewPolicy("example.org", testPublic(1), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	raw := signed(t, envelope.Enrollment, map[string]any{"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": state, "keys": []any{map[string]any{"key": key, "not_before": "2029-01-01T00:00:00Z", "not_after": "2031-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": "host-a_", "explicit": []any{}}}, 1)
	snapshot, _, err := (registry.Loader{Policy: policy, Verifier: verifierFixture{}, Store: storeFixture{}}).Load(registry.Input{Revision: strings.Repeat("1", 40), FirstUse: true, Entries: []registry.Entry{{Path: "enrollments/a.json", Bytes: raw}}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

type fixture struct {
	handler *Handler
	core    *admission.Admitter
	audit   *auditFixture
	clock   *clockFixture
	signer  *signerFixture
}

func setup(t *testing.T) *fixture { return setupLimits(t, 1, 1) }
func setupLimits(t *testing.T, perKey, perName int) *fixture {
	t.Helper()
	a := &auditFixture{}
	clock := &clockFixture{healthy: true}
	signer := &signerFixture{}
	core, err := admission.New(admission.Config{Audience: "example.org", Clock: clock, Startup: admission.Startup{Reading: admission.Reading{UTC: testEpoch, Healthy: true}, Ordered: true}, Registry: snapshotFixture(t, testPublic(2), "active"), Signer: signer, Audit: a, Instance: [16]byte{1}, Limits: &admission.Limits{PerKey: perKey, PerName: perName}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(core)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{handler, core, a, clock, signer}
}
