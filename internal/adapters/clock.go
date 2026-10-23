package adapters

import (
	"context"
	"sync"
	"time"
)

// Reading and Startup are neutral adapter data. Follow-up admission wiring must
// bridge the corresponding named core values; this package imports no unlanded core.
type Reading struct {
	UTC              int64
	Monotonic        time.Duration
	Healthy, Faulted bool
}
type Startup struct {
	Reading Reading
	Ordered bool
}

// ClockEvidence must be an explicit, trusted, nonblocking source. Startup must
// attest actual healthy process-start UTC and ordering against ANY old admission;
// Current must latch transient health loss/backward UTC even between observations.
// No production implementation exists. Tests supply an in-memory implementation.
type ClockEvidence interface {
	Startup(time.Time) (healthy, ordered bool)
	Current() (healthy, faulted bool)
}
type Clock struct {
	mu       sync.Mutex
	start    time.Time
	evidence ClockEvidence
	startup  Startup
	last     Reading
	fenced   bool
	now      func() time.Time
}

// NewClock takes actual process entry time captured with time.Now, preserving
// its monotonic component; constructor-call time must not replace process start.
func NewClock(processStart time.Time, evidence ClockEvidence) *Clock {
	healthy, ordered := false, false
	if evidence != nil {
		healthy, ordered = evidence.Startup(processStart)
	}
	initial := Reading{UTC: processStart.Unix(), Healthy: healthy, Faulted: !healthy || !ordered}
	return &Clock{start: processStart, evidence: evidence, startup: Startup{initial, ordered}, last: initial, fenced: initial.Faulted, now: time.Now}
}
func (c *Clock) Startup() Startup { return c.startup }
func (c *Clock) Now() Reading {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	healthy, faulted := false, true
	if c.evidence != nil {
		healthy, faulted = c.evidence.Current()
	}
	r := Reading{UTC: t.Unix(), Monotonic: t.Sub(c.start), Healthy: healthy}
	if !healthy || faulted || r.UTC < c.last.UTC || r.Monotonic < c.last.Monotonic {
		c.fenced = true
	}
	r.Faulted = c.fenced
	c.last = r
	return r
}
func (c *Clock) Deadline(parent context.Context, at time.Duration) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, c.start.Add(at))
}
