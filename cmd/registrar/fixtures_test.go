package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/registry"
)

// All fixture private keys derive solely from these public fixed test seeds.
func private(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func public(seed byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(private(seed).Public().(ed25519.PublicKey))
}
func signed(t *testing.T, domain envelope.Domain, body map[string]any, seed byte) ([]byte, string) {
	t.Helper()
	pre, id, err := envelope.SigningInput(domain, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private(seed), pre))}, ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return raw, id
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

type testSource struct {
	entries  []registry.Entry
	revision string
	fail     bool
}

func (s *testSource) Read(context.Context) ([]registry.Entry, error) {
	if s.fail {
		return nil, errors.New("unavailable")
	}
	return s.entries, nil
}
func (s *testSource) Verify(revision string, entries []registry.Entry) error {
	if s.fail || revision != s.revision || !reflect.DeepEqual(entries, s.entries) {
		return errors.New("unapproved fixture")
	}
	return nil
}
func (s *testSource) Descends(candidate, previous string) (bool, error) {
	return candidate == s.revision && previous == s.revision, nil
}

type fixtureData struct {
	config                      adapters.Config
	source                      *testSource
	store                       *adapters.FileStore
	initialDigest, enrollmentID string
	signer                      *adapters.Signer
}

func fixture(t *testing.T) *fixtureData {
	t.Helper()
	c := adapters.Config{Audience: "example.org", Revision: strings.Repeat("1", 40), PublisherKey: public(1), Stations: map[string]bool{"host-a": false}, PerKey: 10, PerName: 3, Listen: "127.0.0.1:0"}
	dir := privateDir(t)
	c.HighWater = filepath.Join(dir, "water")
	c.AuditFile = filepath.Join(dir, "audit")
	c.SigningKey = filepath.Join(dir, "key")
	raw, id := signed(t, envelope.Enrollment, map[string]any{"type": "enrollment/1", "host": "host-a", "seq": int64(1), "state": "active", "keys": []any{map[string]any{"key": public(2), "not_before": "2020-01-01T00:00:00Z", "not_after": "2040-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": "host-a_", "explicit": []any{}}}, 1)
	source := &testSource{entries: []registry.Entry{{Path: "enrollments/a.json", Bytes: raw}}, revision: c.Revision}
	store, err := adapters.NewFileStore(c.HighWater)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.NewPolicy(c.Audience, c.PublisherKey, c.Stations)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := (registry.Loader{Policy: policy, Verifier: source, Store: store}).Load(registry.Input{Revision: c.Revision, Entries: source.entries, FirstUse: true}); err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private(9))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.SigningKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := adapters.LoadSigner(c.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureData{c, source, store, digest(t, store), id, signer}
}

const epoch int64 = 1893456000

type testClock struct{}

func (testClock) Now() admission.Reading {
	return admission.Reading{UTC: epoch + 100, Monotonic: 100 * time.Second, Healthy: true}
}
func (testClock) Deadline(ctx context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
func healthyStartup() admission.Startup {
	return admission.Startup{Reading: admission.Reading{UTC: epoch, Healthy: true}, Ordered: true}
}
func proof(t *testing.T) []byte {
	raw, _ := signed(t, envelope.Registration, map[string]any{"type": "registration/1", "key": public(2), "name": "host-a_project_role", "aud": "example.org", "nonce": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)), "iat": "2030-01-01T00:01:40Z", "exp": "2030-01-01T00:02:00Z"}, 2)
	return raw
}
