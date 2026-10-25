package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/registry"
)

// Wrong, missing and nonterminal confirmation cannot commit authority; the exact
// digest commits once. Preview validation itself performs no durable writes.
func TestReconcileExactTerminalConfirmation(t *testing.T) {
	for _, answer := range []string{"wrong", "", "space", "nonterminal", "exact"} {
		t.Run(answer, func(t *testing.T) {
			f := fixture(t)
			counted := &countingStore{FileStore: f.store}
			var out bytes.Buffer
			terminal := func() (io.ReadCloser, error) {
				if answer == "nonterminal" {
					return nil, errors.New("not a terminal")
				}
				text := answer
				if answer == "" {
					text = ""
				} else if answer == "exact" {
					text = digest(t, f.store) + "\n"
				} else if answer == "space" {
					text = digest(t, f.store) + " \n"
				} else {
					text += "\n"
				}
				return io.NopCloser(strings.NewReader(text)), nil
			}
			snapshot, err := reconcile(context.Background(), f.config, f.source, counted, terminal, &out)
			if answer != "exact" {
				if err == nil || snapshot != nil {
					t.Fatal("unconfirmed authority installed")
				}
				if counted.commits != 0 {
					t.Fatal("unconfirmed Store.Commit call")
				}
				if got := digest(t, f.store); got != f.initialDigest {
					t.Fatal("unconfirmed durable write")
				}
			} else if err != nil || snapshot == nil || counted.commits != 1 {
				t.Fatalf("exact confirmation refused: %v", err)
			}
			if !strings.Contains(out.String(), f.config.Revision) || !strings.Contains(out.String(), f.enrollmentID) || !strings.Contains(out.String(), f.initialDigest) {
				t.Fatal("preview omits evidence")
			}
		})
	}
}

// A confirmed process cannot leave reusable freshness behind: a second start
// without reconciliation stays registry-fenced and retains unchanged evidence.
func TestReconcileDoesNotSurviveRestart(t *testing.T) {
	f := fixture(t)
	terminal := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(digest(t, f.store) + "\n")), nil }
	s, err := reconcile(context.Background(), f.config, f.source, f.store, terminal, io.Discard)
	if err != nil || s == nil {
		t.Fatal("confirmed control")
	}
	stored, err := f.store.Load()
	if err != nil || stored.Reconciled {
		t.Fatal("stored evidence claims freshness")
	}
	next, err := startRegistry(context.Background(), f.config, f.source, f.store, false, terminal, io.Discard)
	if err != nil || next != nil {
		t.Fatal("restart reused reconciliation")
	}
	if digest(t, f.store) != f.initialDigest {
		t.Fatal("restart changed evidence")
	}
}

// Missing rollback evidence never becomes implicit bootstrap. An explicit
// pin-specific first-use decision still needs exact interactive confirmation.
func TestReconcileMissingStateNeedsConfiguredPin(t *testing.T) {
	for _, firstUse := range []bool{false, true} {
		t.Run(fmt.Sprint(firstUse), func(t *testing.T) {
			f := fixture(t)
			path := filepath.Join(privateDir(t), "water")
			store, err := adapters.NewFileStore(path, "sha1")
			if err != nil {
				t.Fatal(err)
			}
			if firstUse {
				f.config.FirstUse = f.config.Revision
				badTerminal := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("wrong\n")), nil }
				if snapshot, err := reconcile(context.Background(), f.config, f.source, store, badTerminal, io.Discard); err == nil || snapshot != nil {
					t.Fatal("configured bootstrap skipped confirmation")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("unconfirmed bootstrap wrote state")
				}
			}
			terminal := func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(bootstrapDigest(f.config.Revision) + "\n")), nil
			}
			snapshot, err := reconcile(context.Background(), f.config, f.source, store, terminal, io.Discard)
			if !firstUse {
				if err == nil || snapshot != nil {
					t.Fatal("missing evidence bootstrapped")
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("missing evidence changed")
				}
			} else if err != nil || snapshot == nil {
				t.Fatalf("explicit confirmed bootstrap refused: %v", err)
			}
		})
	}
}

// Explicit first use cannot reinterpret corrupt evidence as absence or overwrite
// it. Valid absent-state bootstrap is exercised by the adjacent positive control.
func TestReconcileCorruptStateCannotBootstrap(t *testing.T) {
	f := fixture(t)
	f.config.FirstUse = f.config.Revision
	if err := os.WriteFile(f.config.HighWater, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	terminal := func() (io.ReadCloser, error) {
		called = true
		return io.NopCloser(strings.NewReader(bootstrapDigest(f.config.Revision) + "\n")), nil
	}
	snapshot, err := reconcile(context.Background(), f.config, f.source, f.store, terminal, io.Discard)
	if err == nil || snapshot != nil || called {
		t.Fatal("corrupt evidence became bootstrap")
	}
	raw, err := os.ReadFile(f.config.HighWater)
	if err != nil || string(raw) != "corrupt" {
		t.Fatal("corrupt evidence overwritten")
	}
}

// A CAS race after preview must not install stale authority or overwrite the
// other writer's state, even after a correct confirmation of the original view.
func TestReconcileConcurrentStateChange(t *testing.T) {
	f := fixture(t)
	terminal := func() (io.ReadCloser, error) {
		old, err := f.store.Inspect()
		if err != nil {
			t.Fatal(err)
		}
		next := old.Clone()
		next.Revision = strings.Repeat("2", 40)
		if err := f.store.Commit(old, *next); err != nil {
			t.Fatal(err)
		}
		return io.NopCloser(strings.NewReader(f.initialDigest + "\n")), nil
	}
	snapshot, err := reconcile(context.Background(), f.config, f.source, f.store, terminal, io.Discard)
	if err == nil || snapshot != nil {
		t.Fatal("stale preview granted authority")
	}
	stored, err := f.store.Load()
	if err != nil || stored.HighWater.Revision != strings.Repeat("2", 40) {
		t.Fatal("concurrent state lost")
	}
}

// A valid-looking confirmation never bypasses a bad signed registry source.
func TestReconcileRejectsInvalidRegistryBeforePrompt(t *testing.T) {
	f := fixture(t)
	f.source.fail = true
	called := false
	terminal := func() (io.ReadCloser, error) {
		called = true
		return io.NopCloser(strings.NewReader(f.initialDigest + "\n")), nil
	}
	snapshot, err := reconcile(context.Background(), f.config, f.source, f.store, terminal, io.Discard)
	if err == nil || snapshot != nil || called {
		t.Fatal("unverified candidate reached confirmation")
	}
	if digest(t, f.store) != f.initialDigest {
		t.Fatal("failed validation changed state")
	}
}

func digest(t *testing.T, s *adapters.FileStore) string {
	t.Helper()
	w, err := s.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	d, err := adapters.HighWaterDigest(w, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var _ registry.Store = (*adapters.FileStore)(nil)

type countingStore struct {
	*adapters.FileStore
	commits int
}

func (s *countingStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	s.commits++
	return s.FileStore.Commit(previous, next)
}

// Interrupting a pending prompt does not commit or publish authority, and an
// overlong or EOF-terminated digest cannot be accepted as an exact terminal line.
func TestReconcileInputBoundaries(t *testing.T) {
	for _, answer := range []string{"no-newline", "overlong", "cancel"} {
		t.Run(answer, func(t *testing.T) {
			f := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			terminal := func() (io.ReadCloser, error) {
				if answer == "cancel" {
					read, write := io.Pipe()
					t.Cleanup(func() { write.Close() })
					cancel()
					return read, nil
				}
				text := f.initialDigest
				if answer == "overlong" {
					text = strings.Repeat("x", 4096) + "\n"
				}
				return io.NopCloser(strings.NewReader(text)), nil
			}
			snapshot, err := reconcile(ctx, f.config, f.source, f.store, terminal, io.Discard)
			if err == nil || snapshot != nil || digest(t, f.store) != f.initialDigest {
				t.Fatal("invalid prompt granted authority")
			}
		})
	}
}
