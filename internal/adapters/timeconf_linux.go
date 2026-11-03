//go:build linux

package adapters

import (
	"context"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

// NewProductionClock consumes only the protected shared option-A policy. Stop
// must be called after admission has drained. Fault closes on the first failure.
func NewProductionClock(ctx context.Context, path string) (clock *Clock, fault <-chan struct{}, stop func(), err error) {
	policy, err := loadTimePolicy(path, protected)
	if err != nil {
		return nil, nil, nil, err
	}
	// Health failures travel through the clock fence; suppress provider std-log output.
	p, err := timeconf.Production(&policy, func(timeconf.Incident) {})
	if err != nil {
		return nil, nil, nil, failure("clock_skew")
	}
	monitor, cancel := context.WithCancel(ctx)
	began := time.Now()
	clock, evidence, err := startProviderClock(monitor, p, time.Now, clockWait, func() time.Duration { return time.Since(began) }, func() (clockObservation, error) {
		// The wall read occurs between these elapsed observations. Comparing interval
		// bounds detects steps without treating syscall measurement jitter as a step.
		first, err := (timeconf.SystemClock{}).Read(monitor)
		if err != nil {
			return clockObservation{}, err
		}
		after, err := (timeconf.SystemClock{}).Read(monitor)
		if err != nil || first.Boot != after.Boot || after.Elapsed < first.Elapsed {
			return clockObservation{}, timeconf.ErrUnavailable
		}
		return clockObservation{ClockPoint: first, latest: after.Elapsed}, nil
	})
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for {
			if clockWait(monitor, 100*time.Millisecond) != nil {
				return
			}
			if ok, _ := evidence.Current(); !ok {
				return
			}
		}
	}()
	return clock, evidence.done, func() { cancel(); <-joined }, nil
}
