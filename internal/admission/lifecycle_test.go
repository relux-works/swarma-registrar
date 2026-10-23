package admission

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Drain fences new operations without effects, preserves already accepted work,
// honors its caller's deadline, and supports repeated/concurrent terminal joins.
func TestDrainJoinsAcceptedWorkAndSealsAdmission(t *testing.T) {
	f := setup(t)
	f.signer.entered = make(chan struct{}, 1)
	f.signer.release = make(chan struct{})
	result := make(chan admissionResult, 1)
	go func() {
		token, err := f.a.Admit(context.Background(), Request{Proof: valid(t, 1)})
		result <- admissionResult{token, err}
	}()
	awaitSignal(t, f.signer.entered)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.a.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending work drain: %v", err)
	}
	if f.a.Ready() {
		t.Fatal("draining readiness opened")
	}
	before := len(f.audit.events())
	rejected(t, f.a, valid(t, 2), refusal.ServiceUnavailable)
	if err := f.a.Refuse(context.Background(), refusal.NameInvalid, 1); !refusal.Is(err, refusal.ServiceUnavailable) {
		t.Fatal("new refusal accepted")
	}
	if err := f.a.RecoverAudit(context.Background()); !refusal.Is(err, refusal.ServiceUnavailable) {
		t.Fatal("new recovery accepted")
	}
	if len(f.audit.events()) != before {
		t.Fatal("post-drain operations wrote audit")
	}
	close(f.signer.release)
	got := awaitResult(t, result)
	if got.err != nil || got.token == "" {
		t.Fatal("accepted positive control lost")
	}
	joins := make(chan error, 2)
	for range 2 {
		go func() { joins <- f.a.Drain(context.Background()) }()
	}
	for range 2 {
		if err := <-joins; err != nil {
			t.Fatal(err)
		}
	}
	f.a.Publish(f.cfg.Registry)
	f.a.ResumeSigning()
	if f.a.Ready() {
		t.Fatal("drain fence reopened")
	}
}

type drainAudit struct {
	*fakeAudit
	entered, release chan struct{}
	fail             bool
}

func (s *drainAudit) Append(ctx context.Context, line []byte) error {
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.fail {
		return errors.New("synthetic local failure")
	}
	return s.fakeAudit.Append(ctx, line)
}

// A detached refusal remains part of Drain after its parent returns. A released
// healthy append joins successfully; a failed/expired append permanently fails
// the shutdown join instead of turning completion into success.
func TestDrainJoinsDetachedCleanupAndReportsFailure(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "deadline"} {
		t.Run(outcome, func(t *testing.T) {
			f := setup(t)
			sink := &drainAudit{fakeAudit: f.audit, entered: make(chan struct{}), release: make(chan struct{}), fail: outcome == "failure"}
			f.cfg.Audit = sink
			a, err := New(f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if err = a.Refuse(canceled, refusal.NameInvalid, 1); !refusal.Is(err, refusal.AuditUnavailable) {
				t.Fatal("canceled parent control")
			}
			awaitSignal(t, sink.entered)
			ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer stop()
			if err = a.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unjoined cleanup: %v", err)
			}
			if outcome == "deadline" {
				f.clock.advance(5 * time.Second)
			} else {
				close(sink.release)
			}
			joined, finish := context.WithTimeout(context.Background(), time.Second)
			defer finish()
			err = a.Drain(joined)
			if outcome == "success" {
				if err != nil || len(f.audit.events()) != 1 {
					t.Fatal("healthy cleanup control", err)
				}
			} else {
				if !refusal.Is(err, refusal.AuditUnavailable) || len(f.audit.events()) != 0 {
					t.Fatal("failed cleanup reported success", err)
				}
				if err = a.Drain(joined); !refusal.Is(err, refusal.AuditUnavailable) {
					t.Fatal("cleanup failure forgotten", err)
				}
			}
		})
	}
}

// A cleanup registered while Drain is already waiting on its accepted parent
// cannot escape the join. The canceled parent itself returns before its child.
func TestDrainIncludesCleanupSpawnedDuringDrain(t *testing.T) {
	f := setup(t)
	f.signer.entered = make(chan struct{}, 1)
	f.signer.release = make(chan struct{})
	sink := &drainAudit{fakeAudit: f.audit, entered: make(chan struct{}), release: make(chan struct{})}
	f.cfg.Audit = sink
	a, err := New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := make(chan admissionResult, 1)
	go func() {
		token, err := a.Admit(ctx, Request{Proof: valid(t, 1)})
		response <- admissionResult{token, err}
	}()
	awaitSignal(t, f.signer.entered)
	joined := make(chan error, 1)
	go func() {
		wait, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		joined <- a.Drain(wait)
	}()
	awaitCondition(t, "drain did not seal", func() bool { return a.life.stopped() })
	cancel()
	got := awaitResult(t, response)
	if got.token != "" || !refusal.Is(got.err, refusal.AuditUnavailable) {
		t.Fatalf("canceled accepted request: %v", got.err)
	}
	awaitSignal(t, sink.entered)
	select {
	case err := <-joined:
		t.Fatalf("child escaped drain: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(sink.release)
	if err = <-joined; err != nil {
		t.Fatal(err)
	}
	if events := f.audit.events(); len(events) != 1 || fmt.Sprint(events[0]["code"]) != "audit_unavailable" {
		t.Fatal("required refusal missing")
	}
}
