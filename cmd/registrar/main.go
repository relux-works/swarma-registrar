// Command registrar serves the pinned registrar API. Production clock evidence
// and authenticated remote audit remain unconfigured and therefore fail closed.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/internal/httpapi"
	"github.com/relux-works/swarma-registrar/registry"
)

type runtime struct {
	handler http.Handler
	drain   func(context.Context) error
	close   func() error
}

var errShutdown = errors.New("shutdown unavailable")

func diagnostic(err error) string {
	if errors.Is(err, errShutdown) {
		return "registrar: shutdown failed"
	}
	return "registrar: startup or serving failed"
}

type dependencies struct {
	loadConfig func(string) (adapters.Config, error)
	open       func(context.Context, adapters.Config, time.Time, bool, terminalOpener, io.Writer) (*runtime, error)
	terminal   terminalOpener
	// listener is an observation hook in package tests, never a CLI/config option.
	listening func(net.Addr)
}

func main() {
	start := time.Now()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, start, dependencies{loadConfig: adapters.LoadConfig, open: openProduction, terminal: openTerminal}); err != nil {
		fmt.Fprintln(os.Stderr, diagnostic(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, _ io.Writer, start time.Time, d dependencies) (result error) {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		_, err := fmt.Fprintln(out, "registrar serve --config <path> [--reconcile] [--loopback-test-http]")
		return err
	}
	if len(args) < 1 || args[0] != "serve" {
		return errors.New("invalid command")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Flag errors may include private command-line paths.
	configPath := flags.String("config", "", "root-owned configuration")
	confirm := flags.Bool("reconcile", false, "confirm rollback evidence for this process")
	plain := flags.Bool("loopback-test-http", false, "permit plain HTTP on a literal loopback address")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *configPath == "" {
		return errors.New("invalid arguments")
	}
	c, err := d.loadConfig(*configPath)
	if err != nil {
		return errors.New("configuration invalid")
	}
	tlsConfig, err := transport(c, *plain)
	if err != nil {
		return err
	}
	r, err := d.open(ctx, c, start, *confirm, d.terminal, out)
	if err != nil {
		return errors.New("service unavailable")
	}
	handlersJoined := true // No handler exists on the early startup-failure paths.
	defer func() {
		if !handlersJoined || r.drain == nil {
			result = errShutdown
			return
		}
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := r.drain(drain); err != nil {
			result = errShutdown
			return
		}
		if err := r.close(); err != nil {
			result = errShutdown
		}
	}()
	if ctx.Err() != nil {
		return errors.New("startup canceled")
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("listener unavailable")
	}
	defer listener.Close()
	if d.listening != nil {
		d.listening(listener.Addr())
	}
	gate := newRequestGate(r.handler)
	handlersJoined = false
	server := &http.Server{Handler: gate, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	// net/http's default TLS/server diagnostics can contain paths or request text;
	// retain static process diagnostics only.
	server.ErrorLog = log.New(io.Discard, "", 0)
	stopped := make(chan struct{})
	shutdownDone := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(shutdown)
			if err != nil {
				_ = server.Close()
			}
			shutdownDone <- err
		case <-stopped:
			shutdownDone <- nil
		}
	}()
	if *plain {
		err = server.Serve(listener)
	} else {
		err = server.ServeTLS(listener, "", "")
	}
	close(stopped)
	shutdownErr := <-shutdownDone
	_ = server.Close()
	// Join handlers even after a failed HTTP grace period, then let the deferred
	// admission drain join detached cleanup before the sink can be closed.
	join, cancelJoin := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelJoin()
	if gate.drain(join) != nil {
		// A live handler could still enqueue admission work. Keep its sink open;
		// main reports failure and process exit reclaims resources.
		return errShutdown
	}
	handlersJoined = true
	if shutdownErr != nil {
		return errShutdown
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return errors.New("server stopped")
}

// openTerminal rejects redirected stdin and then reads the controlling terminal,
// not an injectable flag/environment digest. TCGETS establishes a real terminal.
func openTerminal() (io.ReadCloser, error) {
	var state syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state)))
	if errno != 0 {
		return nil, registryFailure()
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, registryFailure()
	}
	return f, nil
}

type clockBridge struct{ *adapters.Clock }

func (c clockBridge) Now() admission.Reading {
	r := c.Clock.Now()
	return admission.Reading{UTC: r.UTC, Monotonic: r.Monotonic, Healthy: r.Healthy, Faulted: r.Faulted}
}

type auditBridge struct{ *adapters.Audit }

func (a auditBridge) Probe(ctx context.Context, h admission.AuditHead) error {
	return a.Audit.Probe(ctx, adapters.Head{Sequence: h.Sequence, Hash: h.Hash})
}

func wire(c adapters.Config, snapshot *registry.Snapshot, clock admission.Clock, startup admission.Startup, signer admission.Signer, audit admission.Audit, head admission.AuditHead) (*serviceHandler, error) {
	var instance [16]byte
	if _, err := rand.Read(instance[:]); err != nil {
		return nil, errors.New("instance unavailable")
	}
	core, err := admission.New(admission.Config{Audience: c.Audience, Registry: snapshot, Clock: clock, Startup: startup, Signer: signer, Audit: audit, Head: head, Instance: instance, Limits: &admission.Limits{PerKey: c.PerKey, PerName: c.PerName}})
	if err != nil {
		return nil, errors.New("admission unavailable")
	}
	handler, err := httpapi.New(core)
	if err != nil {
		return nil, errors.New("HTTP unavailable")
	}
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if !core.Ready() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, "{\"ready\":false}\n")
				return
			}
			_, _ = io.WriteString(w, "{\"ready\":true}\n")
			return
		}
		handler.ServeHTTP(w, r)
	})
	return &serviceHandler{Handler: httpHandler, drain: core.Drain}, nil
}

func openProduction(ctx context.Context, c adapters.Config, start time.Time, confirm bool, terminal terminalOpener, out io.Writer) (*runtime, error) {
	source, err := adapters.NewGit(c.Repository, c.Revision, c.AllowedSigners)
	if err != nil {
		return nil, err
	}
	store, err := adapters.NewFileStore(c.HighWater)
	if err != nil {
		return nil, err
	}
	signer, err := adapters.LoadSigner(c.SigningKey)
	if err != nil {
		return nil, err
	}
	audit, err := adapters.NewAudit(ctx, c.AuditFile, nil)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*runtime, error) { _ = audit.Close(); return nil, err }
	snapshot, err := startRegistry(ctx, c, source, store, confirm, terminal, out)
	if err != nil {
		if _, writeErr := fmt.Fprintln(out, "Registry fenced; reconciliation refused. Restart with --reconcile after verifying surviving evidence."); writeErr != nil {
			return fail(writeErr)
		}
		snapshot = nil
	}
	clock := adapters.NewClock(start, nil)
	s := clock.Startup()
	h := audit.Head()
	handler, err := wire(c, snapshot, clockBridge{clock}, admission.Startup{Reading: admission.Reading{UTC: s.Reading.UTC, Monotonic: s.Reading.Monotonic, Healthy: s.Reading.Healthy, Faulted: s.Reading.Faulted}, Ordered: s.Ordered}, signer, auditBridge{audit}, admission.AuditHead{Sequence: h.Sequence, Hash: h.Hash})
	if err != nil {
		return fail(err)
	}
	return &runtime{handler: handler, drain: handler.Drain, close: audit.Close}, nil
}
