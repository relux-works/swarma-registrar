package adapters

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/registry"
)

// CAS compares retained evidence beyond its revision. A stale owner-map view
// must not overwrite it; the exact previous state succeeds and stays unreconciled.
func TestReviewStoreFullStateCAS(t *testing.T) {
	store, _ := newStore(t)
	old := water('1')
	id := "sha256:" + strings.Repeat("a", 64)
	old.Hosts["host-a"] = registry.HostWater{Seq: 1, ID: id, History: map[int64]string{1: id}}
	old.NameOwners["legacy"] = "host-a"
	if err := store.Commit(nil, *old); err != nil {
		t.Fatal("bootstrap control")
	}
	stale := old.Clone()
	delete(stale.NameOwners, "legacy")
	next := old.Clone()
	next.Revision = strings.Repeat("2", 40)
	err := store.Commit(stale, *next)
	if err == nil {
		t.Fatal("same-revision stale owner map overwrote evidence")
	}
	wantCode(t, err, registry.RegistryUnavailable)
	state, err := store.Load()
	if err != nil || state.Reconciled || state.HighWater.NameOwners["legacy"] != "host-a" || state.HighWater.Revision != old.Revision {
		t.Fatal("failed CAS changed evidence")
	}
	if err = store.Commit(old, *next); err != nil {
		t.Fatal("matching complete-state control")
	}
}

// A lock already held by another open file description refuses a writer, and a
// symlink lock cannot substitute a stable lock. Releasing/restoring it permits CAS.
func TestReviewStoreLocks(t *testing.T) {
	s, path := newStore(t)
	old := water('1')
	if err := s.Commit(nil, *old); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("lock fixture")
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal("fixture lock")
	}
	wantCode(t, s.Commit(old, *water('2')), registry.RegistryUnavailable)
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal("release fixture lock")
	}
	if err = s.Commit(old, *water('2')); err != nil {
		t.Fatal("released lock control")
	}
	if err = os.Remove(path + ".lock"); err != nil {
		t.Fatal("remove unlocked fixture")
	}
	if err = os.Symlink(path, path+".lock"); err != nil {
		t.Fatal("symlink fixture")
	}
	wantCode(t, s.Commit(water('2'), *water('3')), registry.RegistryUnavailable)
	state, err := s.Load()
	if err != nil || state.HighWater.Revision != water('2').Revision || state.Reconciled {
		t.Fatal("lock refusal damaged state")
	}
}

// PEM decoding must not skip a malformed initial block and use a later key.
// All bytes derive from published test seeds; no configured key file is opened.
func TestReviewSignerSkippedPEM(t *testing.T) {
	der, err := x509.MarshalPKCS8PrivateKey(testPrivate(9))
	if err != nil {
		t.Fatal("synthetic key")
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	for _, prefix := range []string{"-----BEGIN PRIVATE KEY-----\n!invalid-base64!\n-----END PRIVATE KEY-----\n", "-----BEGIN PRIVATE KEY-----\nunterminated\n"} {
		path := filepath.Join(tempDir(t), "fixture.pem")
		write(t, path, append([]byte(prefix), good...), 0600)
		signer, err := LoadSigner(path)
		if err == nil || signer != nil {
			t.Errorf("malformed initial PEM was skipped: accepted=%t", signer != nil)
		} else {
			wantCode(t, err, serviceUnavailable)
			if strings.Contains(err.Error(), path) {
				t.Fatal("path leaked")
			}
		}
		write(t, path, good, 0600)
		signer, err = LoadSigner(path)
		if err != nil {
			t.Fatal("single-block control")
		}
		msg := []byte("fixture message")
		sig, err := signer.Sign(context.Background(), msg)
		if err != nil || !ed25519.Verify(signer.PublicKey(), msg, sig) {
			t.Fatal("control signature")
		}
	}
}

// Both initially unhealthy and later faulted evidence remain fenced after the
// source recovers. A new explicit healthy instance is the nearby valid control.
func TestReviewClockLatches(t *testing.T) {
	start := time.Now()
	e := &clockEvidence{healthy: false, ordered: true}
	c := NewClock(start, e)
	e.healthy = true
	if c.Startup().Reading.Healthy || !c.Now().Faulted {
		t.Fatal("unhealthy startup reopened")
	}
	fresh := NewClock(start, e)
	if r := fresh.Now(); !r.Healthy || r.Faulted {
		t.Fatal("healthy control")
	}
	e.faulted = true
	if !fresh.Now().Faulted {
		t.Fatal("reported fault ignored")
	}
	e.faulted = false
	if !fresh.Now().Faulted {
		t.Fatal("reported fault cleared")
	}
}
