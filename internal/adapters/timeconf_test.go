package adapters

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

func testTimePolicy() timeconf.Policy {
	return timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: 2048 * time.Second, MaxUncertainty: 1500 * time.Millisecond, MaxOffset: 500 * time.Millisecond, MaxRootDistance: time.Second, AuthorityWindow: 300 * time.Second, BackwardTolerance: time.Second, StepTolerance: time.Minute, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
}

type sampleProvider struct {
	sample      timeconf.Sample
	err         error
	starts      int
	secondError bool
}

func (p *sampleProvider) Sample(context.Context) (timeconf.Sample, error) { return p.sample, p.err }
func (p *sampleProvider) StartSample(ctx context.Context) (timeconf.Sample, error) {
	p.starts++
	if p.starts == 2 && p.secondError {
		return timeconf.Sample{}, timeconf.ErrUnavailable
	}
	return p.Sample(ctx)
}
func healthySample(now time.Time) timeconf.Sample {
	return timeconf.Sample{Now: now, AuthorityUntil: now.Add(300 * time.Second), Trusted: true, Fresh: true, Uncertainty: time.Second, Boot: "boot"}
}

// Invalid provider results permanently fence, while adjacent valid bounds pass;
// authority equality is excluded and negative uncertainty cannot be admitted.
func TestProviderSampleBoundaries(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, tc := range []struct {
		name string
		edit func(*sampleProvider)
		bad  bool
	}{
		{"healthy", func(p *sampleProvider) {}, false},
		{"future", func(p *sampleProvider) { p.sample.Now = now.Add(1) }, true},
		{"boot-mismatch", func(p *sampleProvider) { p.sample.Boot = "other" }, true},
		{"empty-boot", func(p *sampleProvider) { p.sample.Boot = "" }, true},
		{"unavailable", func(p *sampleProvider) { p.err = timeconf.ErrUnavailable }, true},
		{"untrusted", func(p *sampleProvider) { p.sample.Trusted = false }, true},
		{"stale", func(p *sampleProvider) { p.sample.Fresh = false }, true},
		{"over-cap", func(p *sampleProvider) { p.sample.Uncertainty = 1500*time.Millisecond + 1 }, true},
		{"cap", func(p *sampleProvider) { p.sample.Uncertainty = 1500 * time.Millisecond }, false},
		{"negative", func(p *sampleProvider) { p.sample.Uncertainty = -1 }, true},
		{"expiry", func(p *sampleProvider) { p.sample.AuthorityUntil = now }, true},
		{"before-expiry", func(p *sampleProvider) { p.sample.AuthorityUntil = now.Add(1) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &sampleProvider{sample: healthySample(now)}
			tc.edit(p)
			e := &providerEvidence{provider: p, ctx: context.Background(), point: func() (clockObservation, error) {
				boot := "boot"
				if tc.name == "empty-boot" && p.sample.Boot == "" {
					boot = ""
				}
				return clockObservation{ClockPoint: timeconf.ClockPoint{Now: now, Boot: boot}}, nil
			}, done: make(chan struct{})}
			ok, fault := e.Current()
			if ok == tc.bad || fault != tc.bad {
				t.Fatal("wrong sample verdict")
			}
			p.sample = healthySample(now)
			p.err = nil
			ok, fault = e.Current()
			if ok == tc.bad || fault != tc.bad {
				t.Fatal("fault recovered in place")
			}
		})
	}
}

type trackingCollector struct{ evidence timeconf.Evidence }

func (c *trackingCollector) Collect(context.Context, timeconf.Policy) (timeconf.Evidence, error) {
	return c.evidence, nil
}

type fixtureTime struct{ point timeconf.ClockPoint }

func (c *fixtureTime) Read(context.Context) (timeconf.ClockPoint, error) { return c.point, nil }

// Real shared-provider validation feeds the adapter: leap, age, offset and root
// distance rejections latch across healthy evidence, with adjacent valid controls.
// No host chrony is consulted.
func TestProviderTrackingBoundaries(t *testing.T) {
	now := time.Unix(10000, 0)
	for _, tc := range []struct {
		name string
		edit func(*timeconf.Tracking)
		bad  bool
	}{
		{"leap", func(v *timeconf.Tracking) { v.Leap = "Insert second" }, true},
		{"normal", func(v *timeconf.Tracking) {}, false},
		{"age-2048", func(v *timeconf.Tracking) { v.Reference = now.Add(-2048 * time.Second) }, true},
		{"age-2047", func(v *timeconf.Tracking) { v.Reference = now.Add(-2047 * time.Second) }, false},
		{"offset-over", func(v *timeconf.Tracking) { v.SystemOffset = 0.500000001 }, true},
		{"offset-equal", func(v *timeconf.Tracking) { v.SystemOffset = 0.5 }, false},
		{"negative-offset-over", func(v *timeconf.Tracking) { v.SystemOffset = -0.500000001 }, true},
		{"negative-offset-equal", func(v *timeconf.Tracking) { v.SystemOffset = -0.5 }, false},
		{"distance-over", func(v *timeconf.Tracking) { v.RootDispersion = 1.000000001 }, true},
		{"distance-equal", func(v *timeconf.Tracking) { v.RootDispersion = 1 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracking := timeconf.Tracking{Address: "192.0.2.1", Leap: "Normal", Stratum: 2, Reference: now.Add(-time.Second)}
			collector := &trackingCollector{timeconf.Evidence{Tracking: tracking, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}}
			tc.edit(&collector.evidence.Tracking)
			c := &fixtureTime{timeconf.ClockPoint{Now: now, Boot: "boot"}}
			p, err := timeconf.New(testTimePolicy(), collector, c, func(timeconf.Incident) {})
			if err != nil {
				t.Fatal(err)
			}
			e := &providerEvidence{provider: p, ctx: context.Background(), point: func() (clockObservation, error) {
				return clockObservation{ClockPoint: c.point, latest: c.point.Elapsed}, nil
			}, done: make(chan struct{})}
			ok, fault := e.Current()
			if ok == tc.bad || fault != tc.bad {
				t.Fatal("wrong tracking verdict")
			}
			collector.evidence.Tracking = tracking
			ok, fault = e.Current()
			if ok == tc.bad || fault != tc.bad {
				t.Fatal("tracking fault recovered in place")
			}
		})
	}
}

// Both start checks bracket four monotonic seconds; a forward wall jump cannot
// shorten the hold, a backward step >1s (also 0.25s) latches, and recheck loss fences.
func TestProviderStartupLifecycle(t *testing.T) {
	for _, kind := range []string{"backward-large", "backward-small", "recheck-loss", "forward", "healthy"} {
		t.Run(kind, func(t *testing.T) {
			base := time.Unix(10000, 0)
			elapsed := time.Duration(0)
			wallShift := time.Duration(0)
			now := func() time.Time { return base.Add(elapsed + wallShift) }
			point := func() (clockObservation, error) {
				return clockObservation{ClockPoint: timeconf.ClockPoint{Now: now(), Elapsed: elapsed, Boot: "boot"}, latest: elapsed}, nil
			}
			p := &sampleProvider{sample: healthySample(base)}
			wait := func(_ context.Context, d time.Duration) error {
				if p.starts != 1 {
					t.Fatal("hold must follow only the first startup check")
				}
				elapsed += d
				if elapsed >= time.Second {
					switch kind {
					case "backward-large":
						wallShift = -2 * time.Second
					case "backward-small":
						wallShift = -250 * time.Millisecond
					case "forward":
						wallShift = 100 * time.Second
					}
				}
				p.sample = healthySample(now())
				if kind == "recheck-loss" && elapsed >= startupHold {
					p.secondError = true
				}
				return nil
			}
			clock, e, err := startProviderClock(context.Background(), p, now, wait, func() time.Duration { return elapsed }, point)
			bad := kind == "backward-large" || kind == "backward-small" || kind == "recheck-loss"
			if (err != nil) != bad {
				t.Fatal("wrong startup verdict", err)
			}
			if bad {
				p.sample = healthySample(base)
				ok, _ := e.Current()
				if ok {
					t.Fatal("recovered")
				}
				return
			}
			if elapsed < 4*time.Second || p.starts != 2 || clock.Startup().Reading.UTC != now().Unix() || !clock.Startup().Ordered {
				t.Fatal("hold or fixed barrier")
			}
			if r := clock.Now(); !r.Healthy || r.Faulted || r.UTC != now().Unix() || r.Monotonic != 0 {
				t.Fatal("healthy post-hold refused")
			}
		})
	}
}

// Root custody, option-A source and cap are enforced through the real guard;
// only ownership/service UID metadata is substituted, with real mode/link I/O.
func TestTimePolicyCustodyAndCap(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "policy")
	p := testTimePolicy()
	save := func() {
		t.Helper()
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		write(t, path, b, 0644)
	}
	save()
	if _, err := loadTimePolicy(path, rootFixture); err != nil {
		t.Fatal("protected control", err)
	}
	for _, tc := range []struct {
		name    string
		owner   uint32
		service int
	}{
		{"not-root-owned", 1001, 1001}, {"root-service", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadTimePolicy(path, func(info os.FileInfo, _ int) bool {
				return protected(ownedInfo{info, tc.owner, info.Mode()}, tc.service)
			})
			wantCode(t, err, configurationInvalid)
		})
	}
	if err := os.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	_, err := loadTimePolicy(path, rootFixture)
	wantCode(t, err, configurationInvalid)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err = loadTimePolicy(link, rootFixture)
	wantCode(t, err, configurationInvalid)
	for _, source := range []timeconf.Source{"off", "chrony-nts-authdata"} {
		p = testTimePolicy()
		if source == timeconf.Off {
			p = timeconf.Policy{}
		}
		p.Source = source
		save()
		_, err := loadTimePolicy(path, rootFixture)
		wantCode(t, err, configurationInvalid)
	}
	p = testTimePolicy()
	p.MaxUncertainty = 1500*time.Millisecond + 1
	save()
	_, err = loadTimePolicy(path, rootFixture)
	wantCode(t, err, configurationInvalid)
	p = testTimePolicy()
	save()
	if _, err := loadTimePolicy(path, rootFixture); err != nil {
		t.Fatal("option-A cap control", err)
	}
}

// A boot change with matching sample/point identities still permanently fences;
// restoring healthy evidence in the original boot cannot reopen the instance.
func TestProviderBootChange(t *testing.T) {
	now := time.Unix(10000, 0)
	p := &sampleProvider{sample: healthySample(now)}
	point := clockObservation{ClockPoint: timeconf.ClockPoint{Now: now, Boot: "boot"}}
	e := &providerEvidence{provider: p, ctx: context.Background(), point: func() (clockObservation, error) { return point, nil }, done: make(chan struct{})}
	if ok, fault := e.Current(); !ok || fault {
		t.Fatal("healthy control")
	}
	p.sample.Boot, point.Boot = "new-boot", "new-boot"
	if ok, fault := e.Current(); ok || !fault {
		t.Fatal("boot change admitted")
	}
	p.sample, point.Boot = healthySample(now), "boot"
	if ok, fault := e.Current(); ok || !fault {
		t.Fatal("boot fault recovered")
	}
}

// A wall/elapsed difference inside the measured read interval is jitter, while
// a negative discontinuity beyond that interval permanently fences.
func TestClockObservationIntervals(t *testing.T) {
	base := time.Unix(10000, 0)
	for _, step := range []time.Duration{-time.Second, 0} {
		p := &sampleProvider{sample: healthySample(base)}
		point := clockObservation{ClockPoint: timeconf.ClockPoint{Now: base, Boot: "boot"}, latest: 10}
		e := &providerEvidence{provider: p, ctx: context.Background(), point: func() (clockObservation, error) { return point, nil }, done: make(chan struct{})}
		if ok, _ := e.Current(); !ok {
			t.Fatal("initial control")
		}
		point = clockObservation{ClockPoint: timeconf.ClockPoint{Now: base.Add(time.Second + step), Elapsed: time.Second + 1, Boot: "boot"}, latest: time.Second + 10}
		ok, _ := e.Current()
		if ok != (step == 0) {
			t.Fatal("interval comparison")
		}
	}
}

// T2/T3: an interrupted 2.9s or 3.5s hold never fixes a barrier or runs the
// second startup check; the complete four-second positive is exercised above.
func TestIncompleteStartupHold(t *testing.T) {
	for _, duration := range []time.Duration{2900 * time.Millisecond, 3500 * time.Millisecond} {
		base := time.Unix(10000, 0)
		elapsed := time.Duration(0)
		calls := 0
		p := &sampleProvider{sample: healthySample(base)}
		clock, _, err := startProviderClock(context.Background(), p, func() time.Time { return base.Add(elapsed) }, func(context.Context, time.Duration) error {
			calls++
			if calls > 1 {
				return context.Canceled
			}
			elapsed = duration
			return nil
		}, func() time.Duration { return elapsed }, func() (clockObservation, error) {
			return clockObservation{ClockPoint: timeconf.ClockPoint{Now: base.Add(elapsed), Elapsed: elapsed, Boot: "boot"}, latest: elapsed}, nil
		})
		if err == nil || clock != nil || p.starts != 1 {
			t.Fatal("short hold qualified")
		}
	}
}

// Normal shutdown cancellation refuses further evidence use without fabricating
// a clock-health incident or changing successful shutdown into a clock-fence exit.
func TestClockCancellationIsNotHealthIncident(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &providerEvidence{ctx: ctx, done: make(chan struct{})}
	if ok, fault := e.Current(); ok || fault {
		t.Fatal("shutdown became health incident")
	}
	select {
	case <-e.done:
		t.Fatal("shutdown latched fault")
	default:
	}
}

// Startup attests only the bound fixed instant, never an unbound or different one.
func TestProviderStartupInstant(t *testing.T) {
	fixed := time.Unix(10000, 123)
	e := &providerEvidence{}
	if healthy, ordered := e.Startup(fixed); healthy || ordered {
		t.Fatal("unbound startup attested")
	}
	e.fixed = fixed
	if healthy, ordered := e.Startup(fixed); !healthy || !ordered {
		t.Fatal("bound control refused")
	}
	if healthy, ordered := e.Startup(fixed.Add(1)); healthy || ordered {
		t.Fatal("different instant attested")
	}
	e.faulted = true
	if healthy, ordered := e.Startup(fixed); healthy || ordered {
		t.Fatal("faulted startup attested")
	}
}
