package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/registry"
)

type registrySource interface {
	registry.Verifier
	Read(context.Context) ([]registry.Entry, error)
}
type waterStore interface {
	registry.Store
	Inspect() (*registry.HighWater, error)
}
type terminalOpener func() (io.ReadCloser, error)

// confirmingStore interposes the operator decision at the real loader's commit
// boundary. It fulfills Store.Commit only after confirmation AND durable CAS;
// no preview store or provisional authority is returned by the loader.
type confirmingStore struct {
	store   registry.Store
	approve func(registry.HighWater) error
}

func (s confirmingStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if err := s.approve(next); err != nil {
		return err
	}
	return s.store.Commit(previous, next)
}

func bootstrapDigest(pin string) string {
	sum := sha256.Sum256([]byte("registrar explicit first use\n" + pin + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func registryFailure() error { return refusal.New(refusal.RegistryUnavailable) }

func startRegistry(ctx context.Context, c adapters.Config, source registrySource, store waterStore, confirm bool, terminal terminalOpener, out io.Writer) (*registry.Snapshot, error) {
	if !confirm {
		if _, err := fmt.Fprintln(out, "Registry fenced; restart with serve --config <path> --reconcile to confirm local evidence."); err != nil {
			return nil, registryFailure()
		}
		return nil, nil
	}
	return reconcile(ctx, c, source, store, terminal, out)
}

func reconcile(ctx context.Context, c adapters.Config, source registrySource, store waterStore, terminal terminalOpener, out io.Writer) (*registry.Snapshot, error) {
	previous, err := store.Inspect()
	if err != nil {
		return nil, registryFailure()
	}
	firstUse := previous == nil && c.FirstUse == c.Revision && c.FirstUse != ""
	if previous == nil && !firstUse {
		return nil, registryFailure()
	}
	entries, err := source.Read(ctx)
	if err != nil {
		return nil, registryFailure()
	}
	policy, err := enrollment.NewPolicy(c.Audience, c.PublisherKey, c.Stations)
	if err != nil {
		return nil, registryFailure()
	}
	gate := confirmingStore{store: store, approve: func(next registry.HighWater) error {
		return confirmEvidence(ctx, c.Revision, previous, next, terminal, out)
	}}
	// The loader may validate retained evidence provisionally, but its Store cannot
	// commit or return any snapshot until the operator supplies freshness evidence.
	snapshot, _, err := (registry.Loader{Policy: policy, Verifier: source, Store: gate}).Load(registry.Input{Revision: c.Revision, Entries: entries, Retained: previous, FirstUse: firstUse, Reconciled: previous != nil})
	if err != nil {
		return nil, registryFailure()
	}
	return snapshot, nil
}

func confirmEvidence(ctx context.Context, pin string, previous *registry.HighWater, next registry.HighWater, terminal terminalOpener, out io.Writer) error {
	var err error
	confirmation := bootstrapDigest(pin)
	highDigest := "absent (explicit configured first use)"
	if previous != nil {
		highDigest, err = adapters.HighWaterDigest(previous)
		if err != nil {
			return registryFailure()
		}
		confirmation = highDigest
	}
	if _, err = fmt.Fprintf(out, "Local high-water digest: %s\nPinned registry revision: %s\nEnrollment IDs to accept:\n", highDigest, pin); err != nil {
		return registryFailure()
	}
	var ids []string
	for _, host := range next.Hosts {
		for _, id := range host.History {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, err = fmt.Fprintln(out, id); err != nil {
			return registryFailure()
		}
	}
	if _, err = fmt.Fprintf(out, "Verify this evidence against trustworthy surviving records outside the restored failure domain.\nType exactly %s to authorize this process only: ", confirmation); err != nil {
		return registryFailure()
	}
	input, err := terminal()
	if err != nil {
		return registryFailure()
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = input.Close()
		case <-done:
		}
	}()
	// Bound input without accepting an EOF-terminated, partial or padded digest.
	reader := bufio.NewReaderSize(io.LimitReader(input, 129), 256)
	line, err := reader.ReadString('\n')
	closeErr := input.Close()
	if err != nil || closeErr != nil || len(line) > 128 || strings.TrimSuffix(line, "\n") != confirmation || ctx.Err() != nil {
		return registryFailure()
	}
	return nil
}
