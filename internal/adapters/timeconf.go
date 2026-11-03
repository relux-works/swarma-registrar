package adapters

import (
	"context"
	"sync"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

const startupHold = 4 * time.Second

type timeProvider interface {
	StartSample(context.Context) (timeconf.Sample, error)
	Sample(context.Context) (timeconf.Sample, error)
}

// clockObservation brackets a wall read with boot elapsed bounds.
type clockObservation struct {
	timeconf.ClockPoint
	latest time.Duration // elapsed upper bound bracketing the wall read
}

// providerEvidence permanently retains observed faults across provider recovery.
type providerEvidence struct {
	mu       sync.Mutex
	provider timeProvider
	ctx      context.Context
	last     clockObservation
	point    func() (clockObservation, error)
	boot     string
	faulted  bool
	fixed    time.Time
	done     chan struct{}
}

func (e *providerEvidence) Startup(instant time.Time) (bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	valid := !e.faulted && !e.fixed.IsZero() && instant.Equal(e.fixed)
	return valid, valid
}
func (e *providerEvidence) Current() (bool, bool) { return e.check(false) }
func (e *providerEvidence) check(start bool) (bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.faulted {
		return false, true
	}
	if e.ctx.Err() != nil {
		return false, false
	}
	var s timeconf.Sample
	var err error
	if start {
		s, err = e.provider.StartSample(e.ctx)
	} else {
		s, err = e.provider.Sample(e.ctx)
	}
	if e.ctx.Err() != nil {
		return false, false
	}
	point, pointErr := e.point()
	now := point.Now
	// Compare subsecond wall progress against independent boot elapsed time.
	// Repeated integer UTC seconds are not backward steps.
	backward := !e.last.Now.IsZero() && (point.Elapsed < e.last.Elapsed || now.Sub(e.last.Now) < point.Elapsed-e.last.latest)
	invalid := err != nil || pointErr != nil || point.Now.IsZero() || point.Elapsed < 0 || point.latest < point.Elapsed || point.Boot != s.Boot || !s.Trusted || !s.Fresh || s.Boot == "" || (!e.last.Now.IsZero() && e.boot != s.Boot) || s.Now.After(now) || !now.Before(s.AuthorityUntil) || s.Uncertainty < 0 || s.Uncertainty > timeconf.PlatformMaxUncertainty
	if invalid || backward {
		if !e.faulted {
			e.faulted = true
			close(e.done)
		}
	}
	e.last, e.boot = point, s.Boot
	return !e.faulted, e.faulted
}

// startProviderClock fixes the serving barrier only after two independent start
// samples separated by a full monotonic hold. Intermediate samples catch faults
// during the hold; the caller owns cancellation and the monitor's lifetime.
func startProviderClock(ctx context.Context, p timeProvider, now func() time.Time, wait func(context.Context, time.Duration) error, elapsed func() time.Duration, point func() (clockObservation, error)) (*Clock, *providerEvidence, error) {
	e := &providerEvidence{provider: p, ctx: ctx, point: point, done: make(chan struct{})}
	if ok, _ := e.check(true); !ok {
		if ctx.Err() != nil {
			return nil, e, ctx.Err()
		}
		return nil, e, failure("clock_skew")
	}
	began := elapsed()
	for elapsed()-began < startupHold {
		remaining := startupHold - (elapsed() - began)
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		if err := wait(ctx, remaining); err != nil {
			return nil, e, err
		}
		if ok, _ := e.check(false); !ok {
			return nil, e, failure("clock_skew")
		}
	}
	if ok, _ := e.check(true); !ok {
		if ctx.Err() != nil {
			return nil, e, ctx.Err()
		}
		return nil, e, failure("clock_skew")
	}
	fixed := now()
	e.fixed = fixed
	clock := NewClock(fixed, e)
	clock.now = now
	return clock, e, nil
}
func clockWait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
