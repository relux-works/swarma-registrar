package main

import (
	"context"
	"fmt"
	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

type reviewDelayedAppend struct {
	auditBridge
	entered   chan struct{}
	release   chan struct{}
	completed chan error
}

func (s *reviewDelayedAppend) Append(ctx context.Context, line []byte) error {
	close(s.entered)
	// Bounded scheduling/I/O pause before the real sink call. No fake persistence.
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	err := s.Audit.Append(ctx, line)
	s.completed <- err
	return err
}

// Canceling an incomplete body schedules the real admission core's bounded local
// refusal cleanup. Shutdown must retain the real file sink until that accepted
// cleanup operation completes. Releasing cleanup before shutdown is the control.
func TestReviewShutdownWaitsForPendingAuditCleanup(t *testing.T) {
	for _, early := range []bool{true, false} {
		t.Run(fmt.Sprint(early), func(t *testing.T) {
			f := fixture(t)
			var sink *reviewDelayedAppend
			enteredRequest := make(chan struct{}, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			address := make(chan net.Addr, 1)
			d := dependencies{loadConfig: func(string) (adapters.Config, error) { return f.config, nil }, terminal: func() (io.ReadCloser, error) { return nil, registryFailure() }, listening: func(a net.Addr) { address <- a }}
			d.open = func(ctx context.Context, c adapters.Config, start time.Time, confirm bool, terminal terminalOpener, out io.Writer) (*runtime, error) {
				a, err := adapters.NewAudit(ctx, c.AuditFile, nil, "sha1")
				if err != nil {
					return nil, err
				}
				sink = &reviewDelayedAppend{auditBridge: auditBridge{a}, entered: make(chan struct{}), release: make(chan struct{}), completed: make(chan error, 1)}
				h := a.Head()
				clock := adapters.NewClock(start, nil)
				startup := clock.Startup()
				handler, err := wire(c, nil, clockBridge{clock}, admission.Startup{Reading: admission.Reading{UTC: startup.Reading.UTC, Monotonic: startup.Reading.Monotonic, Healthy: startup.Reading.Healthy, Faulted: startup.Reading.Faulted}, Ordered: startup.Ordered}, f.signer, sink, admission.AuditHead{Sequence: h.Sequence, Hash: h.Hash})
				if err != nil {
					a.Close()
					return nil, err
				}
				return &runtime{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { enteredRequest <- struct{}{}; handler.ServeHTTP(w, r) }), drain: handler.Drain, close: a.Close}, nil
			}
			ended := make(chan error, 1)
			go func() {
				ended <- run(ctx, []string{"serve", "--config", "fixture", "--loopback-test-http"}, io.Discard, io.Discard, time.Now(), d)
			}()
			var addr net.Addr
			select {
			case addr = <-address:
			case err := <-ended:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("startup timeout")
			}
			conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = fmt.Fprintf(conn, "POST /v1/registration HTTP/1.1\r\nHost: example.org\r\nContent-Type: application/json\r\nContent-Length: 128\r\n\r\n{"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-enteredRequest:
			case <-time.After(time.Second):
				t.Fatal("request not entered")
			}
			conn.Close()
			select {
			case <-sink.entered:
			case <-time.After(time.Second):
				t.Fatal("detached cleanup did not reach real sink wrapper")
			}
			if early {
				close(sink.release)
				if err := <-sink.completed; err != nil {
					t.Fatal("live sink control", err)
				}
				cancel()
				if err := <-ended; err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(f.config.AuditFile)
				if err != nil || len(raw) == 0 {
					t.Fatal("control missing refusal")
				}
				return
			}
			cancel()
			closedEarly := false
			select {
			case err := <-ended:
				if err != nil {
					t.Fatal(err)
				}
				closedEarly = true
			case <-time.After(200 * time.Millisecond):
			}
			close(sink.release)
			err = <-sink.completed
			if !closedEarly {
				select {
				case endErr := <-ended:
					if endErr != nil {
						t.Fatal(endErr)
					}
				case <-time.After(time.Second):
					t.Fatal("shutdown did not complete after cleanup")
				}
			}
			raw, readErr := os.ReadFile(f.config.AuditFile)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if closedEarly || err != nil || len(raw) == 0 {
				t.Fatalf("shutdown completed before pending audit cleanup: returned_early=%t append_error=%v persisted_bytes=%d", closedEarly, err, len(raw))
			}
		})
	}
}
