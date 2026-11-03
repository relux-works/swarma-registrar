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

// ClockEvidence must be an explicit, trusted, bounded source. Startup must
// attest actual healthy process-start UTC and ordering against ANY old admission;
// Current must latch transient health loss/backward UTC even between observations.
// Production uses the shared timeconf provider; tests may inject evidence.
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

// NewClock takes the fixed post-hold process-start time from specification §7,
// preserving its monotonic component. Production uses NewProductionClock to
// establish both provider checks and the full hold before fixing this instant.
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
	healthy, faulted := false, true
	if c.evidence != nil {
		healthy, faulted = c.evidence.Current()
	}
	t := c.now()
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
