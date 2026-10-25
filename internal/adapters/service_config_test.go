package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// Service transport and first-use settings remain strict and pin-specific;
// existing adapter-only configuration remains a valid non-listening input.
func TestServiceConfigFields(t *testing.T) {
	dir := tempDir(t)
	var config map[string]any
	if json.Unmarshal(configBytes(t, dir), &config) != nil {
		t.Fatal("fixture")
	}
	config["listen"] = "127.0.0.1:8443"
	config["tls_certificate"] = filepath.Join(dir, "certificate")
	config["tls_key"] = filepath.Join(dir, "tls-key")
	config["first_use"] = strings.Repeat("1", 40)
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	good, err := ParseConfig(raw)
	if err != nil || good.FirstUse != good.Revision || good.Listen != "127.0.0.1:8443" {
		t.Fatal("valid transport control")
	}
	for _, edit := range []func(map[string]any){
		func(m map[string]any) { m["first_use"] = true }, func(m map[string]any) { m["first_use"] = strings.Repeat("2", 40) },
		func(m map[string]any) { m["listen"] = "localhost:8443" }, func(m map[string]any) { m["listen"] = false },
		func(m map[string]any) { m["tls_key"] = "relative" }, func(m map[string]any) { delete(m, "tls_key") },
		func(m map[string]any) { m["tls_certificate"] = nil }, func(m map[string]any) { m["first_use"] = "" },
		func(m map[string]any) { m["reconciled"] = true },
	} {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			t.Fatal("fixture")
		}
		edit(m)
		bad, _ := json.Marshal(m)
		_, err := ParseConfig(bad)
		wantCode(t, err, configurationInvalid)
		if _, err := ParseConfig(raw); err != nil {
			t.Fatal("valid control")
		}
	}
}

// Inspect distinguishes absence from corruption without granting freshness;
// its canonical-state digest distinguishes the tested revision change.
func TestStoreInspectionNeverAttestsFreshness(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "water")
	s, err := NewFileStore(path, "sha1")
	if err != nil {
		t.Fatal(err)
	}
	w, err := s.Inspect()
	if err != nil || w != nil {
		t.Fatal("absence inspection")
	}
	if _, err := HighWaterDigest(nil, "sha1"); err == nil {
		t.Fatal("absent state had digest")
	}
	w = &registry.HighWater{Revision: strings.Repeat("1", 40), Hosts: map[string]registry.HostWater{}, KeyOwners: map[string]string{}, NameOwners: map[string]string{}}
	if err = s.Commit(nil, *w); err != nil {
		t.Fatal(err)
	}
	inspected, err := s.Inspect()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := HighWaterDigest(inspected, "sha1")
	if err != nil || len(digest) != 71 {
		t.Fatal("digest control")
	}
	inspected.Revision = strings.Repeat("2", 40)
	other, err := HighWaterDigest(inspected, "sha1")
	if err != nil || other == digest {
		t.Fatal("digest ignored state")
	}
	stored, err := s.Load()
	if err != nil || stored.Reconciled || stored.HighWater.Revision != w.Revision {
		t.Fatal("inspection granted or mutated authority")
	}
	if err = os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Inspect(); err == nil {
		t.Fatal("corruption treated as absence")
	}
}
