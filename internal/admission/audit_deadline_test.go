package admission

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

type admissionResult struct {
	token string
	err   error
}

func awaitResult(t *testing.T, result <-chan admissionResult) admissionResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("request remained queued after its own cancellation")
		return admissionResult{}
	}
}
func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("expected audit/signing stage not reached")
	}
}
func awaitCondition(t *testing.T, claim string, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal(claim)
		case <-tick.C:
		}
	}
}
func noDeadlines(c *fakeClock) bool { c.mu.Lock(); defer c.mu.Unlock(); return len(c.deadlines) == 0 }
func checkRetained(t *testing.T, a *Admitter, count int) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.nonces) != count || len(a.keyEvents[public(2)]) != count || len(a.nameEvents["host-a_project_role"]) != count {
		t.Fatal("timeout refunded or duplicated nonce/budget state")
	}
}

// Signal a live cancellation check at the acquisition boundary without changing
// its result. The snapshot precedes the signal, so cancellation cannot turn the
// queued-only narrowing plant into an already-cancelled positive control.
type acquisitionContext struct {
	context.Context
	checked chan struct{}
	ready   func() bool
	once    sync.Once
}

func (c *acquisitionContext) Err() error {
	err := c.Context.Err()
	if err == nil && c.ready() {
		c.once.Do(func() { close(c.checked) })
	}
	return err
}
func waitAcquisition(checked <-chan struct{}) {
	// The original unconditional mutex has no cancellation check until after
	// acquiring. Allow that baseline to reach the same deadline assertion.
	select {
	case <-checked:
	case <-time.After(100 * time.Millisecond):
	}
}

type queuedSigner struct {
	key              ed25519.PrivateKey
	entered, release chan struct{}
	calls            atomic.Int32
	signed           atomic.Bool
}

func (s *queuedSigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }
func (s *queuedSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if s.calls.Add(1) == 1 {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		s.signed.Store(true)
	}
	return ed25519.Sign(s.key, message), nil
}

type queuedClock struct {
	*fakeClock
	signer    *queuedSigner
	observed  chan struct{}
	checked   chan struct{}
	armed     atomic.Bool
	deadlines atomic.Int32
	once      sync.Once
}

func (c *queuedClock) Now() Reading {
	r := c.fakeClock.Now()
	if c.signer.signed.Load() {
		c.armed.Store(true)
		c.once.Do(func() { close(c.observed) })
	}
	return r
}

func (c *queuedClock) Deadline(parent context.Context, at time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := c.fakeClock.Deadline(parent, at)
	if c.deadlines.Add(1) == 1 {
		return &acquisitionContext{Context: ctx, checked: c.checked, ready: c.armed.Load}, cancel
	}
	return ctx, cancel
}

type cancellationClock struct {
	*fakeClock
	deadlines atomic.Int32
	checked   chan struct{}
}

func (c *cancellationClock) Deadline(parent context.Context, at time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := c.fakeClock.Deadline(parent, at)
	if c.deadlines.Add(1) == 2 {
		return &acquisitionContext{Context: ctx, checked: c.checked, ready: func() bool { return true }}, cancel
	}
	return ctx, cancel
}

type queuedAudit struct {
	fakeAudit
	blocked, release chan struct{}
	calls            atomic.Int32
}

func (s *queuedAudit) Append(ctx context.Context, line []byte) error {
	if s.calls.Add(1) == 1 {
		close(s.blocked)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.fakeAudit.Append(ctx, line)
}

// A starts at t=0 and finishes signing at t=4; B starts at t=4 and holds
// local sequencing until its own t=9 deadline. A must return no JWT at t=5,
// retain both debits/nonces, and never wait for B. The fresh control issues.
func TestAuditQueueDeadline(t *testing.T) {
	f := setup(t)
	signer := &queuedSigner{key: private(9), entered: make(chan struct{}), release: make(chan struct{})}
	clock := &queuedClock{fakeClock: f.clock, signer: signer, observed: make(chan struct{}), checked: make(chan struct{})}
	sink := &queuedAudit{blocked: make(chan struct{}), release: make(chan struct{})}
	cfg := f.cfg
	cfg.Signer = signer
	cfg.Clock = clock
	cfg.Audit = sink
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	var workers sync.WaitGroup
	var releaseSigner, releaseAudit sync.Once
	defer func() {
		cancel()
		releaseSigner.Do(func() { close(signer.release) })
		releaseAudit.Do(func() { close(sink.release) })
		workers.Wait()
		f.clock.advance(10 * time.Second)
	}()
	first, second := make(chan admissionResult, 1), make(chan admissionResult, 1)
	p1, p2 := valid(t, 1), valid(t, 2)
	workers.Add(1)
	go func() {
		defer workers.Done()
		token, err := a.Admit(parent, Request{Proof: p1})
		first <- admissionResult{token, err}
	}()
	awaitSignal(t, signer.entered)
	f.clock.advance(4 * time.Second)
	workers.Add(1)
	go func() {
		defer workers.Done()
		token, err := a.Admit(parent, Request{Proof: p2})
		second <- admissionResult{token, err}
	}()
	awaitSignal(t, sink.blocked)
	releaseSigner.Do(func() { close(signer.release) })
	awaitSignal(t, clock.observed)
	waitAcquisition(clock.checked)
	f.clock.advance(time.Second)
	r := awaitResult(t, first)
	if r.token != "" || !refusal.Is(r.err, refusal.AuditUnavailable) {
		t.Fatalf("queued issuance = %q, %v", r.token, r.err)
	}
	select {
	case <-second:
		t.Fatal("later request did not remain under its own t=9 deadline")
	default:
	}
	checkRetained(t, a, 2)
	if a.Ready() {
		t.Fatal("unwritten refusal did not fence readiness")
	}
	f.clock.advance(4 * time.Second)
	r = awaitResult(t, second)
	if r.token != "" || !refusal.Is(r.err, refusal.AuditUnavailable) {
		t.Fatal("later timeout released JWT", r.err)
	}
	awaitCondition(t, "bounded cleanup did not finish", func() bool { return noDeadlines(f.clock) })
	checkRetained(t, a, 2)
	events := sink.events()
	if len(events) != 2 {
		t.Fatalf("local cleanup records=%d, want 2", len(events))
	}
	for _, event := range events {
		if event["outcome"] != "refused" || event["code"] != "audit_unavailable" {
			t.Fatal(event)
		}
	}
	g := setup(t)
	issued(t, g.a, valid(t, 1))
}

// Refuse and RecoverAudit must cancel while another append owns sequencing.
// A cancelled recovery cannot clear the fence, and refusal cannot debit state.
func TestAuditQueueCancellationPaths(t *testing.T) {
	for _, path := range []string{"refusal", "recovery"} {
		t.Run(path, func(t *testing.T) {
			f := setup(t)
			sink := &queuedAudit{blocked: make(chan struct{}), release: make(chan struct{})}
			cfg := f.cfg
			clock := &cancellationClock{fakeClock: f.clock, checked: make(chan struct{})}
			cfg.Clock = clock
			cfg.Audit = sink
			a, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			holder := make(chan admissionResult, 1)
			p := valid(t, 1)
			go func() {
				token, err := a.Admit(context.Background(), Request{Proof: p})
				holder <- admissionResult{token, err}
			}()
			defer func() { close(sink.release); awaitResult(t, holder); f.clock.advance(10 * time.Second) }()
			awaitSignal(t, sink.blocked)
			if path == "recovery" {
				a.fenceAudit()
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan admissionResult, 1)
			started := make(chan struct{})
			go func() {
				close(started)
				var err error
				if path == "refusal" {
					err = a.Refuse(parent, refusal.NameInvalid, 12)
				} else {
					err = a.RecoverAudit(parent)
				}
				result <- admissionResult{err: err}
			}()
			awaitSignal(t, started)
			waitAcquisition(clock.checked)
			cancel()
			r := awaitResult(t, result)
			if !refusal.Is(r.err, refusal.AuditUnavailable) {
				t.Fatal(r.err)
			}
			if a.Ready() {
				t.Fatal("cancelled operation reopened audit fence")
			}
			checkRetained(t, a, 1)
		})
	}
	g := setup(t)
	if err := g.a.RecoverAudit(context.Background()); err != nil {
		t.Fatal("uncontended recovery", err)
	}
	if err := g.a.Refuse(context.Background(), refusal.NameInvalid, 0); !refusal.Is(err, refusal.NameInvalid) {
		t.Fatal("uncontended refusal", err)
	}
	issued(t, g.a, valid(t, 1))
}

type timeoutAudit struct {
	ackCalls atomic.Int32
	fakeAudit
	ackEntered, cleanupEntered chan struct{}
	blockCleanup               bool
	appends                    atomic.Int32
}

func (s *timeoutAudit) Append(ctx context.Context, line []byte) error {
	if s.appends.Add(1) == 2 {
		close(s.cleanupEntered)
		if s.blockCleanup {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	return s.fakeAudit.Append(ctx, line)
}
func (s *timeoutAudit) Acknowledge(ctx context.Context, line []byte) error {
	if s.ackCalls.Add(1) == 1 {
		close(s.ackEntered)
		<-ctx.Done()
		return ctx.Err()
	}
	return s.fakeAudit.Acknowledge(ctx, line)
}

// A total-deadline ack failure returns immediately, then attempts only a local
// refusal under a fresh bounded budget. Successful spooling never reopens the
// fence; failed/blocked spooling cannot extend the response or fabricate a line.
func TestExpiredContextAuditCleanup(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprint("blocked=", blocked), func(t *testing.T) {
			f := setup(t)
			sink := &timeoutAudit{ackEntered: make(chan struct{}), cleanupEntered: make(chan struct{}), blockCleanup: blocked}
			cfg := f.cfg
			cfg.Audit = sink
			a, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			p := valid(t, 1)
			result := make(chan admissionResult, 1)
			go func() {
				token, err := a.Admit(context.Background(), Request{Proof: p})
				result <- admissionResult{token, err}
			}()
			awaitSignal(t, sink.ackEntered)
			f.clock.advance(5 * time.Second)
			r := awaitResult(t, result)
			if r.token != "" || !refusal.Is(r.err, refusal.AuditUnavailable) {
				t.Fatal("deadline response", r.err)
			}
			checkRetained(t, a, 1)
			awaitSignal(t, sink.cleanupEntered)
			if blocked {
				f.clock.advance(4 * time.Second)
				if noDeadlines(f.clock) {
					t.Fatal("cleanup lost its fresh five-second budget")
				}
				f.clock.advance(time.Second)
			}
			awaitCondition(t, "cleanup exceeded its independent budget", func() bool { return noDeadlines(f.clock) })
			events := sink.events()
			want := 2
			if blocked {
				want = 1
			}
			if len(events) != want || events[0]["outcome"] != "issued" {
				t.Fatal("wrong local timeout history", events)
			}
			if !blocked && (events[1]["code"] != "audit_unavailable" || events[1]["outcome"] != "refused" || events[1]["jti"] != p.ID || events[1]["http_status"] != float64(503) || events[1]["jwt_iat"] != nil || events[1]["jwt_exp"] != nil) {
				t.Fatal(events[1])
			}
			if a.Ready() {
				t.Fatal("cleanup implicitly recovered readiness")
			}
			if sink.ackCalls.Load() != 1 {
				t.Fatal("detached local spool attempted remote acknowledgement")
			}
			checkRetained(t, a, 1)
			if !blocked {
				if err := a.RecoverAudit(context.Background()); err != nil {
					t.Fatal("exact-head recovery after spool", err)
				}
				rejected(t, a, p, refusal.NonceReplayed)
				issued(t, a, valid(t, 2))
			}
		})
	}
	g := setup(t)
	issued(t, g.a, valid(t, 1))
}

// Each ordered §6.1 row pins the emitted audit status, including repeated 7a/7c
// and all routing codes. Unknown codes cannot create arbitrary audit statuses.
func TestAuditStatusTable(t *testing.T) {
	rows := []struct {
		order, code string
		http        int64
	}{
		{"1", "endpoint_not_found", 404}, {"2", "method_not_allowed", 405}, {"3", "request_too_large", 413}, {"4", "unsupported_media_type", 415},
		{"5", "registration_malformed", 400}, {"6", "registration_id_mismatch", 400}, {"7a", "registration_signature_invalid", 403}, {"7b", "signature_high_s", 403}, {"7c", "registration_signature_invalid", 403},
		{"8", "registry_unavailable", 503}, {"9", "key_not_enrolled", 403}, {"10", "key_not_valid_now", 403}, {"11", "host_revoked", 403}, {"12", "name_invalid", 400}, {"13", "name_not_permitted", 403},
		{"14", "audience_mismatch", 403}, {"15", "clock_skew", 400}, {"16", "request_not_yet_valid", 403}, {"17", "request_expired", 403}, {"18", "rate_limited", 429}, {"19", "nonce_replayed", 409}, {"20", "service_unavailable", 503}, {"21", "audit_unavailable", 503},
	}
	for _, row := range rows {
		t.Run(row.order+"/"+row.code, func(t *testing.T) {
			f := setup(t)
			code := refusal.Code(row.code)
			if got := status(code); got != row.http {
				t.Errorf("audit status=%d, spec wants %d", got, row.http)
			}
			if err := f.a.Refuse(context.Background(), code, 42); !refusal.Is(err, code) {
				t.Fatal(err)
			}
			events := f.audit.events()
			if len(events) != 1 || events[0]["http_status"] != float64(row.http) || events[0]["code"] != row.code || events[0]["request_bytes"] != float64(42) {
				t.Fatal(events)
			}
			if len(f.a.nonces) != 0 || len(f.a.keyEvents) != 0 || len(f.a.nameEvents) != 0 {
				t.Fatal("routing audit charged authenticated state")
			}
		})
	}
	if status(refusal.Code("unknown")) != 0 {
		t.Fatal("unknown code assigned protocol status")
	}
	g := setup(t)
	issued(t, g.a, valid(t, 1))
	if err := g.a.Refuse(context.Background(), refusal.Code("unknown"), 0); !refusal.Is(err, refusal.ServiceUnavailable) {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprint(g.audit.events()), "unknown") {
		t.Fatal("unknown audit detail leaked")
	}
}
