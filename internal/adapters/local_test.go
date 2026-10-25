package adapters

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	publicEnrollment "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/registry"
)

// Fixed public seeds only; these are test keys, never host credentials.
func testPrivate(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func testPublic(seed byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(testPrivate(seed).Public().(ed25519.PublicKey))
}
func keyFile(t *testing.T, dir string) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(testPrivate(9))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "key.pem")
	write(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	return path
}

// Group/other permissions, symlinks, wrong key encodings and insecure parent
// directories are rejected with no path or key diagnostic. A valid protected
// Ed25519 PKCS8 fixture signs the exact bytes and returns independent public data.
func TestSignerPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0640, 0604, 0644, 0660, 0400} {
		dir := tempDir(t)
		path := keyFile(t, dir)
		os.Chmod(path, mode)
		_, err := LoadSigner(path)
		wantCode(t, err, serviceUnavailable)
		if strings.Contains(err.Error(), path) {
			t.Fatal("path in error")
		}
		os.Chmod(path, 0600)
		signer, err := LoadSigner(path)
		if err != nil {
			t.Fatal("protected control")
		}
		message := []byte("public test message")
		sig, err := signer.Sign(context.Background(), message)
		if err != nil || !ed25519.Verify(signer.PublicKey(), message, sig) {
			t.Fatal("signature control")
		}
		public := signer.PublicKey()
		clear(public)
		if !ed25519.Verify(signer.PublicKey(), message, sig) {
			t.Fatal("public key alias")
		}
	}
	dir := tempDir(t)
	path := keyFile(t, dir)
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	_, err := LoadSigner(link)
	wantCode(t, err, serviceUnavailable)
	write(t, path, []byte("not a private key"), 0600)
	_, err = LoadSigner(path)
	wantCode(t, err, serviceUnavailable)
	path = keyFile(t, dir)
	os.Chmod(dir, 0755)
	_, err = LoadSigner(path)
	wantCode(t, err, serviceUnavailable)
	os.Chmod(dir, 0700)
	signer, err := LoadSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signature, err := signer.Sign(ctx, []byte("message"))
	wantCode(t, err, serviceUnavailable)
	if signature != nil {
		t.Fatal("signature after cancellation")
	}
}

// A well-formed non-Ed25519 PKCS8 key and a FIFO cannot become a signer;
// restoring the fixed public Ed25519 fixture permits exact-byte signing.
func TestSignerAlgorithmAndSpecialFile(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "key.pem")
	key, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal("public wrong-algorithm fixture")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("PKCS8 fixture")
	}
	write(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	_, err = LoadSigner(path)
	wantCode(t, err, serviceUnavailable)
	if err = os.Remove(path); err != nil {
		t.Fatal("remove fixture")
	}
	if err = syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal("FIFO fixture")
	}
	_, err = LoadSigner(path)
	wantCode(t, err, serviceUnavailable)
	if err = os.Remove(path); err != nil {
		t.Fatal("remove FIFO")
	}
	signer, err := LoadSigner(keyFile(t, dir))
	if err != nil {
		t.Fatal("Ed25519 control")
	}
	message := []byte("public control")
	sig, err := signer.Sign(context.Background(), message)
	if err != nil || !ed25519.Verify(signer.PublicKey(), message, sig) {
		t.Fatal("exact signing control")
	}
}

// PEM decoding must not silently discard a preamble or an additional block;
// the same single PKCS8 fixture remains the positive control after each refusal.
func TestSignerFraming(t *testing.T) {
	dir := tempDir(t)
	path := keyFile(t, dir)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read generated fixture")
	}
	for _, bad := range [][]byte{append([]byte("discarded preamble\n"), good...), append(bytes.Clone(good), good...)} {
		write(t, path, bad, 0600)
		_, err = LoadSigner(path)
		wantCode(t, err, serviceUnavailable)
		write(t, path, good, 0600)
		if _, err = LoadSigner(path); err != nil {
			t.Fatal("single-block control")
		}
	}
}

type clockEvidence struct{ healthy, ordered, faulted bool }

func (e *clockEvidence) Startup(time.Time) (bool, bool) { return e.healthy, e.ordered }
func (e *clockEvidence) Current() (bool, bool)          { return e.healthy, e.faulted }

// Missing evidence, unordered startup, transient sync loss and observed backward
// time permanently fence this instance. A fresh explicit healthy source permits
// a new process; waiting/restoring the old source never clears its fault.
func TestClockNoEvidenceAndFence(t *testing.T) {
	start := time.Now()
	absent := NewClock(start, nil)
	if absent.Now().Healthy || !absent.Now().Faulted || absent.Startup().Ordered {
		t.Fatal("nil evidence admitted")
	}
	for _, kind := range []string{"unordered", "sync", "latched", "backward"} {
		t.Run(kind, func(t *testing.T) {
			e := &clockEvidence{healthy: true, ordered: true}
			if kind == "unordered" {
				e.ordered = false
			}
			c := NewClock(start, e)
			switch kind {
			case "sync":
				e.healthy = false
			case "latched":
				e.faulted = true
			case "backward":
				c.now = func() time.Time { return start.Add(-time.Second) }
			}
			if !c.Now().Faulted {
				t.Fatal("fault not fenced")
			}
			e.healthy = true
			e.ordered = true
			e.faulted = false
			c.now = func() time.Time { return start.Add(time.Minute) }
			if !c.Now().Faulted {
				t.Fatal("fence reopened")
			}
			fresh := NewClock(time.Now(), e)
			r := fresh.Now()
			if !fresh.Startup().Ordered || !r.Healthy || r.Faulted || r.Monotonic < 0 {
				t.Fatal("fresh healthy control")
			}
		})
	}
}

// Monotonic deadlines preserve parent cancellation and expired instants without
// sleeps or assumptions about real synchronization (none is implemented here).
func TestClockDeadline(t *testing.T) {
	c := NewClock(time.Now(), nil)
	ctx, cancel := c.Deadline(context.Background(), -time.Second)
	defer cancel()
	<-ctx.Done()
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("expired deadline")
	}
	parent, stop := context.WithCancel(context.Background())
	child, release := c.Deadline(parent, time.Hour)
	defer release()
	if child.Err() != nil {
		t.Fatal("future control")
	}
	stop()
	<-child.Done()
	if child.Err() != context.Canceled {
		t.Fatal("parent not preserved")
	}
}

func water(rev byte) *registry.HighWater {
	return &registry.HighWater{Revision: strings.Repeat(string(rev), 40), Hosts: map[string]registry.HostWater{}, KeyOwners: map[string]string{}, NameOwners: map[string]string{}}
}
func newStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(tempDir(t), "water")
	store, err := NewFileStore(path, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

// Stale/absent CAS expectations cannot overwrite durable evidence. A matching
// expectation can advance it, but local reads always remain unreconciled.
func TestStoreCAS(t *testing.T) {
	store, _ := newStore(t)
	old := water('1')
	next := water('2')
	if err := store.Commit(nil, *old); err != nil {
		t.Fatal(err)
	}
	wantCode(t, store.Commit(water('3'), *next), registry.RegistryUnavailable)
	wantCode(t, store.Commit(nil, *next), registry.RegistryUnavailable)
	state, err := store.Load()
	if err != nil || state.Reconciled || state.HighWater.Revision != old.Revision {
		t.Fatal("CAS changed stored evidence")
	}
	if err = store.Commit(old, *next); err != nil {
		t.Fatal("matching CAS control")
	}
	state, err = store.Load()
	if err != nil || state.Reconciled || state.HighWater.Revision != next.Revision {
		t.Fatal("local freshness invented")
	}
}

// Every persistence-step failure returns an error; visibility after rename may
// already be new. This tests visible bytes, not crash durability or rollback.
// A new store never treats either visible result as reconciled startup evidence.
func TestStoreFailureEveryStep(t *testing.T) {
	for _, step := range []string{"lock", "read", "read_close", "create", "write", "file_sync", "close", "rename", "directory_open", "directory_sync", "directory_close", "unlock", "lock_close"} {
		t.Run(step, func(t *testing.T) {
			store, path := newStore(t)
			old := water('1')
			next := water('2')
			if err := store.Commit(nil, *old); err != nil {
				t.Fatal(err)
			}
			store.before = func(at string) error {
				if at == step {
					return errors.New("injected persistence failure")
				}
				return nil
			}
			wantCode(t, store.Commit(old, *next), registry.RegistryUnavailable)
			restarted, err := NewFileStore(path, "sha1")
			if err != nil {
				t.Fatal(err)
			}
			state, err := restarted.Load()
			if err != nil || state.Reconciled {
				t.Fatal("failure became reconciled")
			}
			expected := old.Revision
			if step == "directory_open" || step == "directory_sync" || step == "directory_close" || step == "unlock" || step == "lock_close" {
				expected = next.Revision
			}
			if state.HighWater.Revision != expected {
				t.Fatal("unexpected visible result")
			}
			store.before = nil
			if err = store.Commit(state.HighWater, *water('3')); err != nil {
				t.Fatal("reconciled-by-caller CAS control")
			}
		})
	}
}

// Independent adapters sharing the stable lock cannot both win the same CAS.
// Missing, corrupt or symlinked files never silently bootstrap stored evidence.
func TestStoreConcurrentAndCorrupt(t *testing.T) {
	store, path := newStore(t)
	old := water('1')
	if err := store.Commit(nil, *old); err != nil {
		t.Fatal(err)
	}
	other, err := NewFileStore(path, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, s := range []*FileStore{store, other} {
		wg.Add(1)
		go func(s *FileStore) { defer wg.Done(); results <- s.Commit(old, *water('2')) }(s)
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else {
			wantCode(t, err, registry.RegistryUnavailable)
		}
	}
	if wins != 1 {
		t.Fatal("multiple CAS winners")
	}
	missing, _ := newStore(t)
	_, err = missing.Load()
	wantCode(t, err, registry.RegistryUnavailable)
	write(t, path, []byte(`{"v":1,"v":1}`), 0600)
	_, err = store.Load()
	wantCode(t, err, registry.RegistryUnavailable)
	os.Remove(path)
	os.Symlink("missing", path)
	_, err = store.Load()
	wantCode(t, err, registry.RegistryUnavailable)
}

func enrollmentFixture(t *testing.T) []byte {
	t.Helper()
	body := map[string]any{"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active", "keys": []any{map[string]any{"key": testPublic(2), "not_before": "2029-01-01T00:00:00Z", "not_after": "2031-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": "host-a_", "explicit": []any{}}}
	pre, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(testPrivate(1), pre))}, registry.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Real signed Git objects feed the landed phased loader and durable store.
// Indeterminate post-rename failure returns no authority; local restart evidence
// alone is refused. An explicit caller reconciliation is a test input, not an
// implemented operator evidence source.
func TestGitStoreLoader(t *testing.T) {
	fixture := newGitFixture(t)
	write(t, filepath.Join(fixture.dir, "enrollments/a.json"), enrollmentFixture(t), 0600)
	fixture.commit(t, true)
	git := fixture.adapter(t)
	entries, err := git.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy, err := publicEnrollment.NewPolicy("example.org", testPublic(1), map[string]bool{"host-a": false})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := newStore(t)
	loader := registry.Loader{ObjectFormat: "sha1", Policy: policy, Verifier: git, Store: store}
	in := registry.Input{Revision: fixture.pin, Entries: entries, FirstUse: true}
	store.before = func(step string) error {
		if step == "directory_sync" {
			return errors.New("injected directory sync failure")
		}
		return nil
	}
	snapshot, next, err := loader.Load(in)
	wantCode(t, err, registry.RegistryUnavailable)
	if snapshot != nil || next != nil {
		t.Fatal("authority despite persistence failure")
	}
	stored, err := store.Load()
	if err != nil || stored.Reconciled {
		t.Fatal("visible result considered reconciled")
	}
	in.FirstUse = false
	in.Retained = stored.HighWater
	in.Reconciled = stored.Reconciled
	store.before = nil
	snapshot, next, err = loader.Load(in)
	wantCode(t, err, registry.RegistryUnavailable)
	if snapshot != nil || next != nil {
		t.Fatal("unreconciled restart authority")
	}
	in.Reconciled = true
	snapshot, next, err = loader.Load(in)
	if err != nil || snapshot == nil || next == nil {
		t.Fatal("explicit reconciliation control")
	}
}
