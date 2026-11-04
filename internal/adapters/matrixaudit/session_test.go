package matrixaudit

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/testtrust"
)

type sessionFixture struct {
	x     *reconciliationFixture
	s     *Session
	lines [][]byte
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	x := newReconciliationFixture(t)
	x.r.Close()
	x.f.c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(x.f.server.Certificate())
	cfg := x.f.c.cfg
	f := &sessionFixture{x: x}
	var err error
	f.s, err = StartSession(testtrust.WithRoots(context.Background(), roots), cfg, []byte("secret-token"), func(ctx context.Context) ([][]byte, error) {
		if ctx.Err() != nil {
			return nil, unavailable
		}
		return f.lines, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.s.Close() })
	return f
}
func attemptContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// Lost receipts select the verified prefix without re-PUT, including a large
// queued refusal-shaped batch. Repeated recovery preserves bytes and sends none.
func TestSessionOrderedReplay(t *testing.T) {
	for _, prefix := range []int{0, 1, 32} {
		t.Run(string(rune('a'+prefix)), func(t *testing.T) {
			f := newSessionFixture(t)
			lines, events := chain(32)
			f.lines = lines
			f.x.events = events[:prefix]
			before := bytes.Join(f.lines, nil)
			if err := f.s.recover(context.Background()); err != nil {
				t.Fatalf("prefix recovery failed: %v", err)
			}
			if !f.s.ready.Load() || f.x.f.puts != 32-prefix || len(f.x.events) != 32 {
				t.Fatal("recovery did not replay exact suffix")
			}
			for i, e := range f.x.events {
				if !f.s.r.match(e, f.mustDelivery(t, lines[i]), e["event_id"].(string)) {
					t.Fatal("replay changed bytes/order")
				}
			}
			if err := f.s.recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.x.f.puts != 32-prefix || !bytes.Equal(before, bytes.Join(f.lines, nil)) {
				t.Fatal("verified prefix re-PUT or local mutation")
			}
		})
	}
}
func (f *sessionFixture) mustDelivery(t *testing.T, line []byte) *Delivery {
	t.Helper()
	d, err := f.s.c.delivery(line)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A changed device or a conflicting/lost retained prefix closes readiness and
// performs zero blind recovery sends. No fixture represents a live HR12 proof.
func TestSessionUncertainSendFences(t *testing.T) {
	for _, mode := range []string{"device", "dedup-loss", "non-prefix", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionFixture(t)
			lines, events := chain(2)
			f.lines = lines
			f.x.events = events[:1]
			if err := f.s.recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			puts := f.x.f.puts
			switch mode {
			case "device":
				f.x.f.who = map[string]any{"user_id": "@audit:example.org", "device_id": "REPLACED"}
			case "dedup-loss":
				f.x.events = nil
			case "non-prefix":
				f.x.events[0]["sender"] = "@foreign:example.org"
			}
			err := f.s.recover(context.Background())
			if mode == "valid" {
				if err != nil || !f.s.ready.Load() {
					t.Fatal("valid recovery control")
				}
			} else if err == nil || f.s.ready.Load() {
				t.Fatal("uncertain/conflicting send reopened")
			}
			if f.x.f.puts != puts {
				t.Fatal("blind recovery PUT after device/prefix loss")
			}
		})
	}
}

// Begin checks before a candidate; a poisoned Complete cannot be retried in the
// same reconciliation. Reopening plus Recover reconstructs the observed prefix.
func TestSessionPrecheckAndReopen(t *testing.T) {
	for _, mode := range []string{"head", "anchor", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newSessionFixture(t)
			ctx, cancel := attemptContext(t)
			defer cancel()
			ctx, done, err := f.s.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			lines, events := chain(1)
			f.lines = lines
			f.x.override = func(w http.ResponseWriter, r *http.Request) bool {
				if mode == "head" && strings.HasSuffix(r.URL.Path, "/messages") && r.URL.Query().Get("filter") == auditFilter && len(f.x.events) > 0 {
					reply := map[string]any{"start": "p1", "chunk": []any{}}
					writeJSON(w, reply)
					return true
				}
				if mode == "anchor" && strings.Contains(r.URL.Path, "/context/") {
					writeJSON(w, map[string]any{"event": map[string]any{"event_id": events[0]["event_id"]}, "start": "p0", "end": "p1", "events_before": []any{}, "events_after": []any{}})
					return true
				}
				return false
			}
			_, err = f.s.Commit(ctx, lines[0])
			done()
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || f.s.ready.Load() {
				t.Fatal("mismatched completion acknowledged")
			}
			if f.s.Readiness() != roomHeadMismatch {
				t.Fatal("specific completion diagnostic lost")
			}
			old := f.s.r
			f.x.override = nil
			ctx2, cancel2 := attemptContext(t)
			defer cancel2()
			_, release, err := f.s.Begin(ctx2)
			if release != nil {
				release()
			}
			if err == nil || f.s.r != old {
				t.Fatal("mismatch retried without reopen/recover")
			}
			if err = f.s.recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			p, _ := f.s.r.Receipt()
			if f.s.r == old || p.Sequence != 1 || !f.s.ready.Load() || f.x.f.puts != 1 {
				t.Fatal("reopen/recover order lost receipt or resent prefix")
			}
		})
	}
}

// Failed GET cannot advance coverage, even if PUT succeeded. This assertion
// detects moving the coverage hook ahead of read-back, independently of JWTs.
func TestSessionReadbackBeforeCoverage(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := attemptContext(t)
	defer cancel()
	ctx, done, err := f.s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f.lines, _ = chain(1)
	handler := f.x.f.server.Config.Handler
	f.x.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/event/") {
			w.WriteHeader(503)
			return
		}
		handler.ServeHTTP(w, r)
	})
	size := f.s.r.size
	_, err = f.s.Commit(ctx, f.lines[0])
	p, _ := f.s.r.Receipt()
	if err == nil || p.Sequence != 0 || f.s.r.size != size {
		t.Fatal("coverage advanced before read-back")
	}
	if f.x.f.puts != 1 {
		t.Fatal("probe did not reach successful PUT")
	}
}

// Waiters expire on their own budgets while another delivery owns a reservation.
// The state mutex stays available and local spool snapshots remain callable.
func TestSessionReservationBudgets(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := attemptContext(t)
	defer cancel()
	done, err := f.s.reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	errors := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			waiter, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer stop()
			_, err := f.s.reserve(waiter)
			errors <- err
		}()
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-errors:
			if err == nil {
				t.Fatal("waiter escaped reservation")
			}
		case <-time.After(time.Second):
			t.Fatal("waiter exceeded own deadline")
		}
	}

	if !f.s.mu.TryLock() {
		t.Fatal("delivery held state mutex across I/O")
	}
	f.s.mu.Unlock()
	if _, err := f.s.snapshot(ctx); err != nil {
		t.Fatal("local snapshot blocked")
	}
}

// A failed coverage journal write after Attempt must never acknowledge a line;
// the adjacent command fixture checks the corresponding JWT and refusal effects.
func TestSessionCoverageWrite(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := attemptContext(t)
	defer cancel()
	ctx, done, err := f.s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f.lines, _ = chain(1)
	if err = os.Chmod(f.s.r.file.Name(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Commit(ctx, f.lines[0]); err == nil {
		t.Fatal("failed coverage write acknowledged")
	}
	if f.x.f.puts != 1 || f.x.f.gets != 1 {
		t.Fatal("write probe did not complete Attempt")
	}
}

func writeJSON(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }

// An observed invalid current policy with retained receipts must fence even at
// restart, before startup would otherwise abort; restoration cannot clear it.
func TestSessionStartupPersistentPolicy(t *testing.T) {
	f := newSessionFixture(t)
	f.lines, f.x.events = chain(1)
	if err := f.s.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.s.Close()
	content(f.x.f, 4)["redact"] = 100
	_, err := StartSession(testtrust.WithRoots(context.Background(), f.s.testRoots), f.s.cfg, f.s.token, f.s.snapshot)
	requireCode(t, err, "audit_room_policy_invalid")
	f.x.f.state = validState()
	_, err = StartSession(testtrust.WithRoots(context.Background(), f.s.testRoots), f.s.cfg, f.s.token, f.s.snapshot)
	requireCode(t, err, "audit_room_policy_invalid")
	if f.x.f.puts != 0 {
		t.Fatal("startup policy fence sent replay")
	}
}

// Released generations, including duplicate done calls, cannot bypass a later
// owner's reservation or mutate coverage; a fresh generation commits normally.
func TestSessionStaleReservationContext(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := attemptContext(t)
	defer cancel()
	stale, done, err := f.s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done()
	for _, held := range []bool{false, true} {
		var release func()
		if held {
			release, err = f.s.reserve(ctx)
			if err != nil {
				t.Fatal(err)
			}
		}
		done()
		lines, _ := chain(1)
		f.lines = lines
		_, err = f.s.Commit(stale, lines[0])
		if err != unavailable {
			t.Fatalf("stale reservation context accepted: %v", err)
		}
		p, _ := f.s.r.Receipt()
		if p.Sequence != 0 || f.x.f.puts != 0 || !f.s.Ready() {
			t.Fatal("stale reservation changed delivery state")
		}
		if held {
			waiter, stop := context.WithTimeout(ctx, 10*time.Millisecond)
			_, err = f.s.reserve(waiter)
			stop()
			if err != unavailable {
				t.Fatal("duplicate done released another generation")
			}
			release()
		}
		f.lines = nil
	}
	fresh, release, err := f.s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	f.lines, _ = chain(1)
	if _, err = f.s.Commit(fresh, f.lines[0]); err != nil {
		t.Fatalf("fresh reservation control failed: %v", err)
	}
}

// done invalidates the context immediately but keeps the reservation held while
// an already-running Commit finishes; neither a waiter nor a second Commit wins.
func TestSessionReleaseDuringCommit(t *testing.T) {
	f := newSessionFixture(t)
	ctx, cancel := attemptContext(t)
	defer cancel()
	reserved, done, err := f.s.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f.lines, _ = chain(1)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(proceed) }) }
	defer unblock()
	snapshot := f.s.snapshot
	f.s.snapshot = func(ctx context.Context) ([][]byte, error) {
		select {
		case entered <- struct{}{}:
			select {
			case <-proceed:
			case <-ctx.Done():
				return nil, unavailable
			}
		default:
		}
		return snapshot(ctx)
	}
	result := make(chan error, 1)
	go func() { _, err := f.s.Commit(reserved, f.lines[0]); result <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("commit did not reach snapshot")
	}
	if _, err = f.s.Commit(reserved, f.lines[0]); err != unavailable {
		t.Fatal("concurrent Commit reused generation")
	}
	done()
	waiter, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	_, err = f.s.reserve(waiter)
	stop()
	if err != unavailable {
		t.Fatal("done released a running Commit")
	}
	unblock()
	if err = <-result; err != nil {
		t.Fatalf("running Commit control failed: %v", err)
	}
	release, err := f.s.reserve(ctx)
	if err != nil {
		t.Fatal("completed Commit did not release reservation")
	}
	release()
	if _, err = f.s.Commit(reserved, f.lines[0]); err != unavailable {
		t.Fatal("done context revived after Commit")
	}
}

// Public construction exposes no roots field and rejects the fixture's private
// CA; only the internal test-context hook admits the same TLS session.
func TestSessionProductionTrust(t *testing.T) {
	if _, exposed := reflect.TypeFor[Config]().FieldByName("Roots"); exposed {
		t.Fatal("public configuration exposes custom roots")
	}
	f := newSessionFixture(t)
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := newClient(f.s.cfg, f.s.token)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.http.Transport.(*transport).tls.RootCAs != nil {
		t.Fatal("production client selected custom roots")
	}
	_, err = StartSession(context.Background(), f.s.cfg, f.s.token, f.s.snapshot)
	requireCode(t, err, "audit_room_unavailable")
	if f.x.f.puts != 0 {
		t.Fatal("untrusted construction sent an audit event")
	}
	s, err := StartSession(testtrust.WithRoots(context.Background(), f.s.testRoots), f.s.cfg, f.s.token, f.s.snapshot)
	if err != nil {
		t.Fatalf("isolated test trust control failed: %v", err)
	}
	defer s.Close()
	if !s.Ready() {
		t.Fatal("trusted session did not become ready")
	}
}
