package matrixaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
)

// Snapshot validates local custody/schema and returns an immutable complete chain.
type Snapshot func(context.Context) ([][]byte, error)

// Session owns delivery reservations, startup/recovery and Complete-only commits.
// The mutex protects reservation transitions only; it never spans network I/O.
// Start Run once, cancel its context and join it before Close.
type Session struct {
	mu         sync.Mutex
	busy       bool
	changed    chan struct{}
	wake       chan struct{}
	cfg        Config
	token      []byte
	snapshot   Snapshot
	c          *Client
	r          *Reconciliation
	ready      atomic.Bool
	diagnostic atomic.Value
}

type reservationKey struct{}

func (s *Session) reserve(ctx context.Context) (func(), error) {
	for {
		if ctx.Err() != nil {
			return nil, unavailable
		}
		s.mu.Lock()
		if !s.busy {
			s.busy = true
			s.mu.Unlock()
			return func() { s.mu.Lock(); s.busy = false; close(s.changed); s.changed = make(chan struct{}); s.mu.Unlock() }, nil
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, unavailable
		case <-changed:
		}
	}
}
func requestBudget(ctx context.Context) *Budget {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	return NewBudget(deadline)
}
func (s *Session) failed() error {
	code := roomUnavailable
	if s.r != nil && s.r.Readiness() != "" {
		code = s.r.Readiness()
	}
	s.diagnostic.Store(code)
	s.ready.Store(false)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return unavailable
}
func (s *Session) discard() {
	if s.r != nil {
		s.r.Close()
		s.r = nil
	}
	if s.c != nil {
		s.c.Close()
		s.c = nil
	}
	s.ready.Store(false)
}

// StartSession loads no files or credentials: token must be loaded once by startup.
// OpenReconciliation always precedes Recover; neither may be skipped on retry.
func StartSession(ctx context.Context, cfg Config, token []byte, snapshot Snapshot) (*Session, error) {
	s := &Session{cfg: cfg, token: bytes.Clone(token), snapshot: snapshot, changed: make(chan struct{}), wake: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if snapshot == nil {
		return nil, unavailable
	}
	if err := s.open(ctx, requestBudget(ctx)); err != nil {
		s.discard()
		return nil, err
	}
	lines, err := snapshot(ctx)
	if err != nil || s.r.Precheck(ctx, requestBudget(ctx), lines) != nil {
		s.failed()
	} else {
		s.ready.Store(true)
	}
	return s, nil
}
func (s *Session) open(ctx context.Context, b *Budget) error {
	s.discard()
	lines, err := s.snapshot(ctx)
	if err != nil {
		return unavailable
	}
	c, err := newClient(s.cfg, s.token)
	if err != nil {
		return err
	}
	s.c = c
	startupErr := c.startup(ctx, b, len(lines) != 0, func(ctx context.Context, b *Budget) error { return c.ReconcileHead(ctx, b, nil, nil) })
	if startupErr != nil && (startupErr != roomPolicyInvalid || c.binding == nil) {
		return startupErr
	}
	s.r, err = c.OpenReconciliation(ctx, b, lines)
	if err != nil {
		return err
	}
	if startupErr != nil && len(s.r.state.Receipts) > 0 {
		return s.r.fence(ctx, b, roomPolicyInvalid, "")
	}
	return s.r.Recover(ctx, b, lines)
}

// Begin checks readiness inside a request's original deadline before its issued
// line exists. Its returned reservation must cover append and acknowledgement.
func (s *Session) Begin(ctx context.Context) (context.Context, func(), error) {
	done, err := s.reserve(ctx)
	if err != nil {
		return ctx, nil, err
	}
	b := requestBudget(ctx)
	lines, err := s.snapshot(ctx)
	if !s.ready.Load() || err != nil || s.r.Precheck(ctx, b, lines) != nil {
		s.failed()
		done()
		return ctx, nil, unavailable
	}
	return context.WithValue(ctx, reservationKey{}, s), done, nil
}

// Commit returns a hash only after Reconciliation.Complete durably covers this
// exact read-back. Attempt success and Position alone never acknowledge a line.
func (s *Session) Commit(ctx context.Context, line []byte) ([32]byte, error) {
	if ctx.Value(reservationKey{}) != s {
		done, err := s.reserve(ctx)
		if err != nil {
			return [32]byte{}, err
		}
		defer done()
	}
	if !s.ready.Load() {
		return [32]byte{}, s.failed()
	}
	b := requestBudget(ctx)
	lines, err := s.snapshot(ctx)
	if err != nil || s.deliver(ctx, b, lines, line) != nil {
		return [32]byte{}, s.failed()
	}
	current, err := s.snapshot(ctx)
	if err != nil {
		return [32]byte{}, s.failed()
	}
	if _, err = s.r.local(ctx, b, current); err != nil || b.check(ctx) != nil {
		return [32]byte{}, s.failed()
	}
	return sha256.Sum256(line), nil
}
func (s *Session) deliver(ctx context.Context, b *Budget, lines [][]byte, line []byte) error {
	local, err := s.r.local(ctx, b, lines)
	if err != nil {
		return err
	}
	p, previous := s.r.Receipt()
	n := int(p.Sequence)
	if n >= len(local) || !bytes.Equal(lines[n], line) {
		return unavailable
	}
	var want *Position
	if n != 0 {
		want = &p
	}
	if err = s.c.ReconcileHead(ctx, b, want, previous); err != nil {
		return s.r.failure(ReadinessCode(err.Error()))
	}
	if err = s.r.policy(ctx, b, n != 0); err != nil {
		return err
	}
	d, err := s.c.Delivery(line)
	if err != nil {
		return err
	}
	v, err := d.Attempt(ctx, b)
	if err != nil {
		return err
	}
	if err = s.r.Complete(ctx, v, lines); err != nil {
		return err
	}
	return b.check(ctx)
}

// recover uses a separate budget for opening/prefix recovery, then one budget
// per suffix line. It never retains or returns a JWT or changes nonce state.
func (s *Session) recover(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	done, err := s.reserve(ctx)
	if err != nil {
		cancel()
		return err
	}
	defer done()
	err = s.open(ctx, requestBudget(ctx))
	cancel()
	if err != nil {
		return s.failed()
	}
	for {
		ctx, cancel = context.WithTimeout(parent, 5*time.Second)
		lines, e := s.snapshot(ctx)
		p, _ := s.r.Receipt()
		if e == nil && p.Sequence == int64(len(lines)) {
			e = s.r.Precheck(ctx, requestBudget(ctx), lines)
			// Refusals may have appended while the network checks were running.
			var current [][]byte
			if e == nil {
				current, e = s.snapshot(ctx)
			}
			if e == nil && len(current) == len(lines) {
				s.ready.Store(true)
				cancel()
				return nil
			}
		} else if e == nil && p.Sequence < int64(len(lines)) {
			e = s.deliver(ctx, requestBudget(ctx), lines, lines[p.Sequence])
		} else {
			e = unavailable
		}
		cancel()
		if e != nil {
			return s.failed()
		}
	}
}

// Run is the single recovery worker. Backoff resets only after full equality.
func (s *Session) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		}
		delay := time.Second
		for {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if s.recover(ctx) == nil {
				break
			}
			// failed signals are coalesced into this worker, never another attempt.
			select {
			case <-s.wake:
			default:
			}
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done, err := s.reserve(ctx)
	if err != nil {
		return err
	}
	defer done()
	s.discard()
	return nil
}

// Ready reports only completed delivery/recovery state, without network I/O.
func (s *Session) Ready() bool { return s.ready.Load() }

// Readiness retains the static diagnostic separately from admission HTTP codes.
func (s *Session) Readiness() ReadinessCode {
	if s.Ready() {
		return ""
	}
	if code := s.diagnostic.Load(); code != nil {
		return code.(ReadinessCode)
	}
	return roomUnavailable
}
