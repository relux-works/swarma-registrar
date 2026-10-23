package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/registry"
)

type ownedInfo struct {
	os.FileInfo
	uid  uint32
	mode os.FileMode
}

func (i ownedInfo) Sys() any          { return &syscall.Stat_t{Uid: i.uid} }
func (i ownedInfo) Mode() os.FileMode { return i.mode }

// This host cannot create root-owned fixtures. Only ownership metadata is
// substituted; mode/content and actual unprivileged rejection remain real I/O.
func rootFixture(info os.FileInfo, uid int) bool {
	return protected(ownedInfo{info, 0, info.Mode()}, 1001)
}
func tempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal("fixture directory mode")
	}
	return path
}
func write(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		if err = os.Chmod(path, 0600); err != nil {
			t.Fatal("fixture writable mode")
		}
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal("fixture write")
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("fixture mode")
	}
}
func wantCode(t *testing.T, err error, code refusal.Code) {
	t.Helper()
	if !refusal.Is(err, code) {
		t.Fatalf("error %v, want %s", err, code)
	}
}
func configBytes(t *testing.T, root string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"v": 1, "audience": "example.org", "repository": root, "revision": strings.Repeat("1", 40), "allowed_signers": filepath.Join(root, "allowed"), "publisher_key": testPublic(1), "stations": map[string]bool{"host-a": false}, "high_water": filepath.Join(root, "water"), "signing_key": filepath.Join(root, "signer"), "audit_file": filepath.Join(root, "audit")})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Root ownership and absence of service write access are required, including
// rejection of a root service account. The metadata control is not a claim of
// privileged fixture creation on this unprivileged test host.
func TestConfigOwnership(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "config")
	raw := configBytes(t, dir)
	write(t, path, raw, 0444)
	write(t, filepath.Join(dir, "allowed"), []byte("public pin fixture"), 0444)
	_, err := LoadConfig(path)
	wantCode(t, err, configurationInvalid)
	info, _ := os.Stat(path)
	for _, bad := range []struct {
		uid     uint32
		mode    os.FileMode
		service int
	}{{1, 0444, 1001}, {0, 0464, 1001}, {0, 0446, 1001}, {0, 0444, 0}, {0, os.ModeDir | 0555, 1001}} {
		if protected(ownedInfo{info, bad.uid, bad.mode}, bad.service) {
			t.Fatal("unsafe metadata accepted")
		}
	}
	if !protected(ownedInfo{info, 0, 0444}, 1001) {
		t.Fatal("protected control")
	}
	c, err := loadConfig(path, rootFixture)
	if err != nil || c.Revision != strings.Repeat("1", 40) {
		t.Fatal("validated fixture load")
	}
	write(t, filepath.Join(dir, "allowed"), []byte("public pin fixture"), 0666)
	_, err = loadConfig(path, rootFixture)
	wantCode(t, err, configurationInvalid)
}

// Strict startup parsing rejects extra fields, lossy values, invalid pins,
// paths/audiences and limit coercion while admitting its unchanged positive input.
func TestConfigStrict(t *testing.T) {
	dir := tempDir(t)
	good := configBytes(t, dir)
	edits := []func(map[string]any){func(m map[string]any) { m["extra"] = true }, func(m map[string]any) { delete(m, "audience") }, func(m map[string]any) { m["v"] = 2 }, func(m map[string]any) { m["revision"] = "main" }, func(m map[string]any) { m["repository"] = "relative" }, func(m map[string]any) { m["audience"] = "https://example.org" }, func(m map[string]any) { m["per_key"] = 0 }, func(m map[string]any) { m["per_name"] = 4 }, func(m map[string]any) { m["per_key"] = 1.5 }, func(m map[string]any) { m["stations"] = map[string]any{"host-a": "false"} }}
	for _, edit := range edits {
		var m map[string]any
		json.Unmarshal(good, &m)
		edit(m)
		bad, _ := json.Marshal(m)
		_, err := ParseConfig(bad)
		wantCode(t, err, configurationInvalid)
		if _, err = ParseConfig(good); err != nil {
			t.Fatal("valid control")
		}
	}
	for _, bad := range [][]byte{append([]byte("\xef\xbb\xbf"), good...), []byte(`{"v":1,"v":1}`), []byte(`{"v":1e0}`)} {
		_, err := ParseConfig(bad)
		wantCode(t, err, configurationInvalid)
	}
}

// The configured audience uses Matrix's ASCII grammar without normalization;
// malformed syntax and invalid station hosts fail before policy construction.
func TestConfigAudienceAndHosts(t *testing.T) {
	dir := tempDir(t)
	good := configBytes(t, dir)
	check := func(audience string, stations map[string]any, valid bool) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal("config fixture")
		}
		m["audience"] = audience
		m["stations"] = stations
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal("config fixture")
		}
		c, err := ParseConfig(raw)
		if !valid {
			wantCode(t, err, configurationInvalid)
			return
		}
		if err != nil || c.Audience != audience {
			t.Fatal("audience spelling changed")
		}
	}
	hosts := map[string]any{"host-a": false, "-node": true}
	for _, audience := range []string{"", "https://example.org", "user@example.org", "example.org/", "example.org:", "example.org:100000", "example.org:+1", "éxample.org", "example_org", "::1", "[::1", "[::1]x", "[127.0.0.1]", "[fe80::1%eth0]", strings.Repeat("a", 256)} {
		check(audience, hosts, false)
		check("example.org", hosts, true)
	}
	for _, audience := range []string{"Example.ORG", "example.org:8448", "127.0.0.1", "[2001:db8::1]", "[::1]:8448", strings.Repeat("a", 255)} {
		check(audience, hosts, true)
	}
	for _, host := range []string{"", "HOST", "host_a", "host.a", "host/a"} {
		check("example.org", map[string]any{host: false}, false)
		check("example.org", hosts, true)
	}
}

// Protected-file checks never follow final symlinks, including public pins.
// Restoring the unchanged regular fixture admits configuration with metadata
// ownership substitution only (not a privileged filesystem acceptance claim).
func TestConfigSymlink(t *testing.T) {
	dir := tempDir(t)
	path, allowed := filepath.Join(dir, "config"), filepath.Join(dir, "allowed")
	write(t, path, configBytes(t, dir), 0444)
	write(t, allowed, []byte("public pin fixture"), 0444)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("symlink fixture")
	}
	_, err := loadConfig(link, rootFixture)
	wantCode(t, err, configurationInvalid)
	if err = os.Remove(allowed); err != nil {
		t.Fatal("remove pin fixture")
	}
	if err = os.Symlink(path, allowed); err != nil {
		t.Fatal("pin symlink fixture")
	}
	_, err = loadConfig(path, rootFixture)
	wantCode(t, err, configurationInvalid)
	if err = os.Remove(allowed); err != nil {
		t.Fatal("remove pin symlink")
	}
	write(t, allowed, []byte("public pin fixture"), 0444)
	if _, err = loadConfig(path, rootFixture); err != nil {
		t.Fatal("regular control")
	}
}

type gitFixture struct{ dir, key, allowed, pin string }

func command(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_LAZY_FETCH=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture command %s failed", args[0])
	}
	return strings.TrimSpace(string(out))
}
func newGitFixture(t *testing.T) *gitFixture {
	t.Helper()
	dir := tempDir(t)
	key := filepath.Join(dir, "key")
	command(t, dir, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	command(t, repo, "git", "init", "--initial-branch=main")
	for name, value := range map[string]string{"user.name": "Fixture Maintainer", "user.email": "fixture@example.org", "gpg.format": "ssh", "user.signingkey": key, "gpg.ssh.program": "/usr/bin/ssh-keygen", "commit.gpgsign": "true"} {
		command(t, repo, "git", "config", name, value)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal("public fixture key")
	}
	allowed := filepath.Join(dir, "allowed")
	write(t, allowed, append([]byte("fixture@example.org "), pub...), 0444)
	if err := os.Mkdir(filepath.Join(repo, "enrollments"), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(repo, "enrollments/a.json"), []byte("first"), 0600)
	f := &gitFixture{repo, key, allowed, ""}
	f.commit(t, true)
	return f
}
func (f *gitFixture) commit(t *testing.T, signed bool) {
	t.Helper()
	command(t, f.dir, "git", "add", "enrollments")
	args := []string{"git"}
	if !signed {
		args = append(args, "-c", "commit.gpgsign=false")
	}
	args = append(args, "commit", "--allow-empty", "-m", "Fixture commit")
	command(t, f.dir, args...)
	f.pin = command(t, f.dir, "git", "rev-parse", "HEAD")
}
func (f *gitFixture) adapter(t *testing.T) *Git {
	t.Helper()
	g, err := newGit(f.dir, f.pin, f.allowed, rootFixture)
	if err != nil {
		t.Fatal("Git fixture adapter")
	}
	return g
}

// Unsigned commits and signatures outside the explicit allowlist fail closed;
// the paired signed commit is accepted without consulting machine credentials.
func TestGitUnsignedOrWrongSigner(t *testing.T) {
	f := newGitFixture(t)
	signed := f.pin
	f.commit(t, false)
	_, err := f.adapter(t).Read(context.Background())
	wantCode(t, err, registry.RegistryUnavailable)
	f.pin = signed
	g := f.adapter(t)
	entries, err := g.Read(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatal("signed control")
	}
	other := newGitFixture(t)
	g.signers = other.allowed
	_, err = g.Read(context.Background())
	wantCode(t, err, registry.RegistryUnavailable)
	g.signers = f.allowed
	if err = g.Verify(f.pin, entries); err != nil {
		t.Fatal("allowed signer control")
	}
}

// Verification binds the complete supplied entry set and exact commit; dirty
// worktree data, omitted/changed entries and symbolic pins cannot substitute it.
func TestGitEntryBinding(t *testing.T) {
	f := newGitFixture(t)
	g := f.adapter(t)
	entries, err := g.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]registry.Entry{nil, {{Path: entries[0].Path, Bytes: []byte("changed"), Kind: registry.Regular}}, {{Path: "enrollments/other.json", Bytes: entries[0].Bytes, Kind: registry.Regular}}, {{Path: entries[0].Path, Bytes: entries[0].Bytes, Kind: registry.Symlink}}} {
		wantCode(t, g.Verify(f.pin, bad), registry.RegistryUnavailable)
	}
	wantCode(t, g.Verify(strings.Repeat("a", 40), entries), registry.RegistryUnavailable)
	if _, err = newGit(f.dir, "main", f.allowed, rootFixture); err == nil {
		t.Fatal("symbolic pin accepted")
	}
	write(t, filepath.Join(f.dir, "enrollments/a.json"), []byte("dirty"), 0600)
	again, err := g.Read(context.Background())
	if err != nil || !bytes.Equal(again[0].Bytes, []byte("first")) {
		t.Fatal("working tree became authority")
	}
	if err = g.Verify(f.pin, entries); err != nil {
		t.Fatal("exact control")
	}
}

// Nonregular enrollment entries cannot disappear from a candidate or become
// ordinary file bytes; a regular signed candidate is the positive control.
func TestGitSymlinkedEntry(t *testing.T) {
	for _, kind := range []string{"file", "root", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := newGitFixture(t)
			good := f.pin
			switch kind {
			case "file":
				os.Remove(filepath.Join(f.dir, "enrollments/a.json"))
				if err := os.Symlink("target", filepath.Join(f.dir, "enrollments/a.json")); err != nil {
					t.Fatal(err)
				}
			case "root":
				os.RemoveAll(filepath.Join(f.dir, "enrollments"))
				if err := os.Symlink("target", filepath.Join(f.dir, "enrollments")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				os.Mkdir(filepath.Join(f.dir, "enrollments/b.json"), 0700)
				write(t, filepath.Join(f.dir, "enrollments/b.json/file"), []byte("data"), 0600)
			}
			f.commit(t, true)
			_, err := f.adapter(t).Read(context.Background())
			wantCode(t, err, registry.RegistryUnavailable)
			f.pin = good
			if _, err = f.adapter(t).Read(context.Background()); err != nil {
				t.Fatal("regular control")
			}
		})
	}
}

// Ancestry rejects a separate signed history and unavailable old objects, but
// recognizes the pinned commit's real parent. False becomes registry_rollback
// in the landed loader; missing ancestry is registry_unavailable.
func TestGitNonDescendant(t *testing.T) {
	f := newGitFixture(t)
	first := f.pin
	f.commit(t, true)
	g := f.adapter(t)
	command(t, f.dir, "git", "checkout", "--orphan", "other")
	write(t, filepath.Join(f.dir, "enrollments/a.json"), []byte("unrelated"), 0600)
	f.commit(t, true)
	other := f.pin
	ok, err := g.Descends(g.pin, other)
	if err != nil || ok {
		t.Fatal("unrelated history accepted")
	}
	_, err = g.Descends(g.pin, strings.Repeat("0", 40))
	wantCode(t, err, registry.RegistryUnavailable)
	ok, err = g.Descends(g.pin, first)
	if err != nil || !ok {
		t.Fatal("descendant control")
	}
}
