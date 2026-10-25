package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// Both profiles flow through strict startup parsing and the Git constructor.
// This constructor test uses only public signer text and does not claim commit
// authentication; invalid IDs never reach Git or a signer-file read.
func TestProtectedConfigAndGitFormat(t *testing.T) {
	for _, profile := range []struct {
		format       string
		width, other int
	}{{"sha1", 40, 64}, {"sha256", 64, 40}} {
		t.Run(profile.format, func(t *testing.T) {
			dir := tempDir(t)
			var obj map[string]any
			if err := json.Unmarshal(configBytes(t, dir), &obj); err != nil {
				t.Fatal(err)
			}
			obj["object_format"], obj["revision"] = profile.format, strings.Repeat("a", profile.width)
			good, _ := json.Marshal(obj)
			c, err := ParseConfig(good)
			if err != nil || c.ObjectFormat != profile.format {
				t.Fatalf("config control: %v", err)
			}
			allowed := filepath.Join(dir, "allowed")
			write(t, allowed, []byte("public fixture"), 0444)
			if g, err := newGit(dir, c.Revision, allowed, c.ObjectFormat, rootFixture); err != nil || g.objectFormat != profile.format {
				t.Fatalf("Git constructor control: %v", err)
			}
			for _, id := range []string{strings.Repeat("a", profile.other), strings.Repeat("a", profile.width-1), strings.Repeat("a", profile.width+1), strings.Repeat("A", profile.width), "abcdef1", "main", strings.Repeat("a", profile.width-1) + "g"} {
				obj["revision"] = id
				raw, _ := json.Marshal(obj)
				_, err := ParseConfig(raw)
				wantCode(t, err, configurationInvalid)
				g, err := newGit(dir, id, allowed, profile.format, rootFixture)
				wantCode(t, err, registry.RegistryUnavailable)
				if g != nil {
					t.Fatal("invalid revision constructed Git source")
				}
			}
		})
	}
}

// Missing/unknown profiles fail before creating files or accepting startup
// configuration. Exact supported profiles are exercised by the neighboring test.
func TestAdapterObjectFormatRequired(t *testing.T) {
	dir := tempDir(t)
	for _, format := range []string{"", "SHA1", "sha512"} {
		var obj map[string]any
		if err := json.Unmarshal(configBytes(t, dir), &obj); err != nil {
			t.Fatal(err)
		}
		if format == "" {
			delete(obj, "object_format")
		} else {
			obj["object_format"] = format
		}
		raw, _ := json.Marshal(obj)
		_, err := ParseConfig(raw)
		wantCode(t, err, configurationInvalid)
		g, err := newGit(dir, strings.Repeat("a", 40), filepath.Join(dir, "missing"), format, rootFixture)
		wantCode(t, err, registry.RegistryUnavailable)
		if g != nil {
			t.Fatal("unknown profile constructed Git")
		}
		path := filepath.Join(dir, "water")
		s, err := NewFileStore(path, format)
		wantCode(t, err, registry.RegistryUnavailable)
		if s != nil {
			t.Fatal("unknown profile constructed store")
		}
		a, err := NewAudit(context.Background(), path, nil, format)
		wantCode(t, err, auditUnavailable)
		if a != nil {
			t.Fatal("unknown profile constructed audit")
		}
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("unknown profile created file")
		}
	}
}

// The store/digest and audit retain their configured profile across writes and
// restart. Cross-format revisions cannot replace state, append a line, alter the
// audit head, or be adopted on restart. Both own-format controls persist.
func TestProtectedStoreAndAuditFormat(t *testing.T) {
	for _, profile := range []struct {
		format, other     string
		width, otherWidth int
	}{{"sha1", "sha256", 40, 64}, {"sha256", "sha1", 64, 40}} {
		t.Run(profile.format, func(t *testing.T) {
			dir := tempDir(t)
			path := filepath.Join(dir, "water")
			s, err := NewFileStore(path, profile.format)
			if err != nil {
				t.Fatal(err)
			}
			w := water('a')
			w.Revision = strings.Repeat("a", profile.width)
			if err = s.Commit(nil, *w); err != nil {
				t.Fatal("valid commit", err)
			}
			good, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if digest, err := HighWaterDigest(w, profile.format); err != nil || digest == "" {
				t.Fatal("valid digest", err)
			}
			if digest, err := HighWaterDigest(w, profile.other); err == nil || digest != "" {
				t.Fatal("cross-format digest")
			}
			bad := w.Clone()
			bad.Revision = strings.Repeat("a", profile.otherWidth)
			wantCode(t, s.Commit(w, *bad), registry.RegistryUnavailable)
			unchanged, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(good, unchanged) {
				t.Fatal("refusal changed state bytes")
			}
			wrong, err := NewFileStore(path, profile.other)
			if err != nil {
				t.Fatal(err)
			}
			_, err = wrong.Load()
			wantCode(t, err, registry.RegistryUnavailable)
			if stored, err := s.Load(); err != nil || stored.Reconciled || stored.HighWater.Revision != w.Revision {
				t.Fatal("valid restart", err)
			}
			auditPath := filepath.Join(dir, "audit")
			a, err := NewAudit(context.Background(), auditPath, nil, profile.format)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.Close() })
			line := editAudit(t, auditLine(t, 1, firstHead().Hash), func(m map[string]any) { m["registry_revision"] = w.Revision })
			badLine := editAudit(t, line, func(m map[string]any) { m["registry_revision"] = bad.Revision })
			wantCode(t, a.Append(context.Background(), badLine), auditUnavailable)
			if a.Head() != firstHead() {
				t.Fatal("bad revision changed audit head")
			}
			if raw, err := os.ReadFile(auditPath); err != nil || len(raw) != 0 {
				t.Fatal("bad revision appended bytes")
			}
			if err = a.Append(context.Background(), line); err != nil {
				t.Fatal("valid audit control", err)
			}
			head := a.Head()
			if err = a.Close(); err != nil {
				t.Fatal(err)
			}
			wrongAudit, err := NewAudit(context.Background(), auditPath, nil, profile.other)
			wantCode(t, err, auditUnavailable)
			if wrongAudit != nil {
				wrongAudit.Close()
				t.Fatal("cross-format chain adopted")
			}
			restarted, err := NewAudit(context.Background(), auditPath, nil, profile.format)
			if err != nil {
				t.Fatal("valid audit restart", err)
			}
			defer restarted.Close()
			if restarted.Head() != head {
				t.Fatal("restart changed audit head")
			}
		})
	}
}
