package main

import (
	"context"
	"net/http"
	"sync"
)

// requestGate joins handlers after forced connection cancellation too: Server.Close
// cancels connections but does not itself join their ServeHTTP calls.
type requestGate struct {
	next   http.Handler
	mu     sync.Mutex
	sealed bool
	active int
	done   chan struct{}
}

func newRequestGate(next http.Handler) *requestGate {
	return &requestGate{next: next, done: make(chan struct{})}
}
func (g *requestGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.sealed {
		g.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	g.active++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.active--
		if g.sealed && g.active == 0 {
			close(g.done)
		}
		g.mu.Unlock()
	}()
	g.next.ServeHTTP(w, r)
}
func (g *requestGate) drain(ctx context.Context) error {
	g.mu.Lock()
	if !g.sealed {
		g.sealed = true
		if g.active == 0 {
			close(g.done)
		}
	}
	done := g.done
	g.mu.Unlock()
	select {
	case <-done:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type serviceHandler struct {
	http.Handler
	drain func(context.Context) error
}

func (h *serviceHandler) Drain(ctx context.Context) error { return h.drain(ctx) }
