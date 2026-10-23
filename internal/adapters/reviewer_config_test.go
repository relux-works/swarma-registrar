package adapters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Strict fields, types, clean literal paths and input caps fail before startup;
// each malformed variant is paired with the same complete supported config.
func TestReviewConfigVariants(t *testing.T) {
	dir := tempDir(t)
	good := configBytes(t, dir)
	edits := []func(map[string]any){
		func(m map[string]any) { m["revision"] = strings.Repeat("A", 40) },
		func(m map[string]any) { m["allowed_signers"] = nil },
		func(m map[string]any) { m["repository"] = dir + "/../repo" },
		func(m map[string]any) { m["signing_key"] = dir + "/key\x00other" },
		func(m map[string]any) { m["stations"] = []any{} },
		func(m map[string]any) { m["publisher_key"] = "invalid" },
		func(m map[string]any) { m["per_key"] = true },
		func(m map[string]any) { m["per_name"] = "1" },
		func(m map[string]any) { m["v"] = nil },
	}
	for _, edit := range edits {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		raw, _ := json.Marshal(m)
		_, err := ParseConfig(raw)
		wantCode(t, err, configurationInvalid)
		if _, err = ParseConfig(good); err != nil {
			t.Fatal("valid schema control")
		}
	}
	duplicate := append([]byte(`{"\u0076":1,`), good[1:]...)
	for _, raw := range [][]byte{duplicate, append(bytes.Clone(good), []byte("{}")...), bytes.Repeat([]byte(" "), 65537)} {
		_, err := ParseConfig(raw)
		wantCode(t, err, configurationInvalid)
	}
	path := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal("FIFO fixture")
	}
	_, err := LoadConfig(path)
	wantCode(t, err, configurationInvalid)
	if strings.Contains(err.Error(), path) {
		t.Fatal("path in config error")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal("remove fixture fifo")
	}
	write(t, path, good, 0444)
	_, err = LoadConfig(path)
	wantCode(t, err, configurationInvalid)
	write(t, filepath.Join(dir, "allowed"), []byte("public fixture"), 0444)
	if _, err = loadConfig(path, rootFixture); err != nil {
		t.Fatal("root-metadata fixture control")
	}
}
