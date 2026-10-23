package admission

import (
	"context"
	"sync"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// lifecycle keeps accepted calls and their detached refusal writes in one join.
// Children register before their accepted parent completes, including during drain.
type lifecycle struct {
	mu      sync.Mutex
	closing bool
	work    int
	done    chan struct{}
	failed  bool
}

func (l *lifecycle) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return false
	}
	l.work++
	return true
}
func (l *lifecycle) child() { l.mu.Lock(); l.work++; l.mu.Unlock() }
func (l *lifecycle) finish(failed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed = l.failed || failed
	l.work--
	if l.closing && l.work == 0 {
		close(l.done)
	}
}
func (l *lifecycle) stopped() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.closing }

// Drain permanently stops new Admit, Refuse and RecoverAudit work and waits for
// accepted calls AND their detached bounded refusal appends. It never cancels or
// extends those operations' existing budgets. The caller first stops HTTP/input.
// Timeout or any failed detached append is a failed drain: do not close the sink
// or report successful shutdown. A subsequent call can wait for quiescence but
// cannot erase a recorded cleanup failure or reopen admission.
func (a *Admitter) Drain(ctx context.Context) error {
	l := &a.life
	l.mu.Lock()
	if !l.closing {
		l.closing = true
		l.done = make(chan struct{})
		if l.work == 0 {
			close(l.done)
		}
	}
	done := l.done
	l.mu.Unlock()
	select {
	case <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		l.mu.Lock()
		failed := l.failed
		l.mu.Unlock()
		if failed {
			return deny(refusal.AuditUnavailable)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
