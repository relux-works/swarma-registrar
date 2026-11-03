package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/adapters"
)

// Missing production policy refuses before any opener; loopback test mode keeps
// the existing injected opener path without requiring production clock authority.
func TestServeRequiresTimePolicy(t *testing.T) {
	sentinel := errors.New("opened")
	for _, plain := range []bool{false, true} {
		opened := false
		args := []string{"serve", "--config", "fixture"}
		if plain {
			args = append(args, "--loopback-test-http")
		}
		d := dependencies{loadConfig: func(string) (adapters.Config, error) { return adapters.Config{Listen: "127.0.0.1:0"}, nil }, open: func(context.Context, adapters.Config, time.Time, bool, terminalOpener, io.Writer) (*runtime, error) {
			opened = true
			return nil, sentinel
		}}
		if err := run(context.Background(), args, io.Discard, io.Discard, time.Now(), d); err == nil || opened != plain {
			t.Fatal("policy gate or loopback injection")
		}
	}
}

// A latched clock fault exits only after successful drain and sink close; drain
// failure keeps the sink open. Drain or close failure retains shutdown error.
func TestClockFenceDrainPrecedence(t *testing.T) {
	for _, kind := range []string{"drain", "close", "healthy"} {
		fail := kind == "drain"
		closeFailure := kind == "close"
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		fault := make(chan struct{})
		close(fault)
		drained, closed := false, false
		d := dependencies{loadConfig: func(string) (adapters.Config, error) { return adapters.Config{Listen: "127.0.0.1:0"}, nil }, open: func(context.Context, adapters.Config, time.Time, bool, terminalOpener, io.Writer) (*runtime, error) {
			return &runtime{fault: fault, drain: func(context.Context) error {
				drained = true
				if fail {
					return errShutdown
				}
				return nil
			}, close: func() error {
				if !drained {
					t.Fatal("close before drain")
				}
				closed = true
				if closeFailure {
					return errShutdown
				}
				return nil
			}}, nil
		}}
		err := run(ctx, []string{"serve", "--config", "fixture", "--loopback-test-http"}, io.Discard, io.Discard, time.Now(), d)
		if !drained || closed == fail {
			t.Fatal("drain/close order")
		}
		if (fail || closeFailure) && !errors.Is(err, errShutdown) || (!fail && !closeFailure) && !errors.Is(err, errClockFence) {
			t.Fatal("wrong exit classification", err)
		}
	}
}
