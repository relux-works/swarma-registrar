//go:build linux

package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

type healthySystemClockProvider struct{ boot string }

func (p healthySystemClockProvider) Sample(context.Context) (timeconf.Sample, error) {
	// Keep provider authority healthy even during the injected 250ms wall step.
	s := healthySample(time.Now().Add(-time.Second))
	s.Boot = p.boot
	return s, nil
}

func (p healthySystemClockProvider) StartSample(ctx context.Context) (timeconf.Sample, error) {
	return p.Sample(ctx)
}

func startSystemClockTest(t *testing.T, shift *time.Duration) (*Clock, *providerEvidence) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	initial, err := (timeconf.SystemClock{}).Read(ctx)
	if err != nil {
		t.Fatal("initial SystemClock read:", err)
	}
	began := time.Now()
	// Match NewProductionClock's two-read observation, including its guards.
	observe := func() (clockObservation, error) {
		first, err := (timeconf.SystemClock{}).Read(ctx)
		if err != nil {
			return clockObservation{}, err
		}
		after, err := (timeconf.SystemClock{}).Read(ctx)
		if err != nil || first.Boot != after.Boot || after.Elapsed < first.Elapsed {
			return clockObservation{}, timeconf.ErrUnavailable
		}
		return clockObservation{ClockPoint: first, latest: after.Elapsed}, nil
	}
	point := func() (clockObservation, error) {
		observation, err := observe()
		if shift != nil {
			observation.Now = observation.Now.Add(*shift)
		}
		return observation, err
	}
	if shift == nil {
		point = observe
	}
	clock, evidence, err := startProviderClock(ctx, healthySystemClockProvider{initial.Boot}, time.Now, clockWait, func() time.Duration { return time.Since(began) }, point)
	if err != nil {
		t.Fatal("real SystemClock startup:", err)
	}
	if startup := clock.Startup(); !startup.Ordered || !startup.Reading.Healthy || startup.Reading.Faulted {
		t.Fatal("healthy startup refused:", startup)
	}
	return clock, evidence
}

// With a healthy fake provider, production SystemClock observations survive the
// real four-second startup hold and 300 Current checks without a refusal. This
// Linux-only check needs no chrony and assumes the host clock is not stepped.
func TestSystemClockAvailability(t *testing.T) {
	_, evidence := startSystemClockTest(t, nil)
	const checks = 300
	refusals := 0
	for range checks {
		if err := clockWait(evidence.ctx, time.Millisecond); err != nil {
			t.Fatal("availability check deadline:", err)
		}
		if healthy, faulted := evidence.Current(); !healthy || faulted {
			refusals++
		}
	}
	if refusals != 0 {
		t.Fatalf("real SystemClock refused %d of %d checks", refusals, checks)
	}
	select {
	case <-evidence.done:
		t.Fatal("healthy observations latched fault")
	default:
	}
}

// After healthy real-SystemClock startup, one injected 250ms backward wall step
// latches the registrar fault; restoring unmodified observations cannot reopen it.
func TestSystemClockBackwardStepLatches(t *testing.T) {
	shift := time.Duration(0)
	clock, evidence := startSystemClockTest(t, &shift)
	if healthy, faulted := evidence.Current(); !healthy || faulted {
		t.Fatal("healthy control refused")
	}
	shift = -250 * time.Millisecond
	if healthy, faulted := evidence.Current(); healthy || !faulted {
		t.Fatal("injected backward step admitted")
	}
	select {
	case <-evidence.done:
	default:
		t.Fatal("backward step did not close fault channel")
	}
	shift = 0
	if healthy, faulted := evidence.Current(); healthy || !faulted {
		t.Fatal("restored observations cleared fault")
	}
	if reading := clock.Now(); reading.Healthy || !reading.Faulted {
		t.Fatal("clock did not retain fault:", reading)
	}
}
