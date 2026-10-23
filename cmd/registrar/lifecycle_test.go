package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/adapters"
)

// Failed/expired admission drain is a failed shutdown with a static error, and
// cannot close the sink as if work had joined. The successful control closes it.
func TestShutdownReportsDrainFailure(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "expired", false: "healthy"}[fail], func(t *testing.T) {
			f := fixture(t)
			d := testDependencies(t, f, true, true)
			original := d.open
			closed := false
			var cleanup func() error
			d.open = func(ctx context.Context, c adapters.Config, start time.Time, confirm bool, terminal terminalOpener, out io.Writer) (*runtime, error) {
				r, err := original(ctx, c, start, confirm, terminal, out)
				if err != nil {
					return nil, err
				}
				cleanup = r.close
				realClose := r.close
				r.close = func() error { closed = true; return realClose() }
				if fail {
					drain := r.drain
					r.drain = func(context.Context) error {
						expired, cancel := context.WithCancel(context.Background())
						cancel()
						return drain(expired)
					}
				}
				return r, nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listening := make(chan net.Addr, 1)
			d.listening = func(addr net.Addr) { listening <- addr }
			ended := make(chan error, 1)
			go func() {
				ended <- run(ctx, []string{"serve", "--config", "fixture", "--loopback-test-http"}, io.Discard, io.Discard, time.Now(), d)
			}()
			select {
			case <-listening:
			case err := <-ended:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("startup")
			}
			cancel()
			var err error
			select {
			case err = <-ended:
			case <-time.After(time.Second):
				t.Fatal("shutdown")
			}
			if fail {
				if !errors.Is(err, errShutdown) || diagnostic(err) != "registrar: shutdown failed" || closed {
					t.Fatal("failed drain reported success/closed sink", err)
				}
				if cleanup != nil {
					_ = cleanup()
				}
			} else if err != nil || !closed {
				t.Fatal("healthy drain control", err)
			}
		})
	}
}

// Sealing the handler gate waits for already entered HTTP work even when its
// caller times out; no later request can enter, and release allows a clean join.
func TestHTTPHandlerJoinAfterCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	gate := newRequestGate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { close(entered); <-release }))
	ended := make(chan struct{})
	go func() { gate.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); close(ended) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := gate.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("active handler escaped", err)
	}
	rejected := httptest.NewRecorder()
	gate.ServeHTTP(rejected, httptest.NewRequest("GET", "/", nil))
	if rejected.Code != 503 {
		t.Fatal("sealed gate reopened")
	}
	close(release)
	<-ended
	if err := gate.drain(context.Background()); err != nil {
		t.Fatal("released control", err)
	}
}
