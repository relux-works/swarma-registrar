package adapters

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func auditConfigMap(t *testing.T, dir string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(configBytes(t, dir), &m); err != nil {
		t.Fatal(err)
	}
	m["audit_homeserver"] = "https://example.org"
	m["audit_room"] = "!audit:example.org"
	m["audit_user"] = "@registrar-audit:example.org"
	m["audit_token"] = filepath.Join(dir, "token")
	m["audit_retired_localparts"] = []any{}
	return m
}
func auditConfigJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Each malformed field refuses without returning configuration; an unchanged valid profile passes beside it (no network adapter is invoked).
func TestAuditConfigInvalid(t *testing.T) {
	dir := tempDir(t)
	cases := []struct {
		name, field string
		value       any
	}{
		{"http", "audit_homeserver", "http://example.org"},
		{"unicode-scheme", "audit_homeserver", "httpſ://example.org"},
		{"slash", "audit_homeserver", "https://example.org/"},
		{"path", "audit_homeserver", "https://example.org/path"},
		{"query", "audit_homeserver", "https://example.org?x=y"},
		{"empty-query", "audit_homeserver", "https://example.org?"},
		{"userinfo", "audit_homeserver", "https://user@example.org"},
		{"fragment", "audit_homeserver", "https://example.org#x"},
		{"empty-fragment", "audit_homeserver", "https://example.org#"},
		{"unicode-host", "audit_homeserver", "https://é.example"},
		{"encoded-host", "audit_homeserver", "https://%65xample.org"},
		{"backslash", "audit_homeserver", `https://example.org\other`},
		{"space", "audit_homeserver", "https://example.org "},
		{"control", "audit_homeserver", "https://example.org\n"},
		{"zero-port", "audit_homeserver", "https://example.org:0"},
		{"large-port", "audit_homeserver", "https://example.org:65536"},
		{"alias", "audit_room", "#audit:example.org"},
		{"room-server", "audit_room", "!audit:other.example"},
		{"room-empty-id", "audit_room", "!:example.org"},
		{"room-empty-server", "audit_room", "!audit:"},
		{"user-case-server", "audit_user", "@registrar-audit:EXAMPLE.org"},
		{"user-port", "audit_user", "@registrar-audit:example.org:8448"},
		{"user-dot", "audit_user", "@registrar-audit:example.org."},
		{"user-uppercase", "audit_user", "@Registrar-audit:example.org"},
		{"user-overlength", "audit_user", "@" + strings.Repeat("a", 243) + ":example.org"},
		{"user-invalid", "audit_user", "@audit/name:example.org"},
		{"user-non-ascii", "audit_user", "@аudit:example.org"},
		{"user-empty", "audit_user", "@:example.org"},
		{"user-no-sigil", "audit_user", "registrar-audit:example.org"},
		{"retired-duplicate", "audit_retired_localparts", []any{"old-audit", "old-audit"}},
		{"retired-mxid", "audit_retired_localparts", []any{"@old-audit:example.org"}},
		{"retired-uppercase", "audit_retired_localparts", []any{"Old-audit"}},
		{"retired-invalid", "audit_retired_localparts", []any{"old/audit"}},
		{"retired-overlength", "audit_retired_localparts", []any{strings.Repeat("a", 243)}},
		{"retired-current", "audit_retired_localparts", []any{"registrar-audit"}},
		{"retired-null-entry", "audit_retired_localparts", []any{nil}},
		{"retired-wrong-entry", "audit_retired_localparts", []any{true}},
		{"token-relative", "audit_token", "token"},
		{"token-parent", "audit_token", dir + "/../token"},
		{"token-dot", "audit_token", dir + "/./token"},
		{"token-empty-component", "audit_token", dir + "//token"},
		{"token-nul", "audit_token", dir + "/token\x00"},
		{"unknown", "audit_ca", "pin"},
	}
	for _, field := range []string{"audit_homeserver", "audit_room", "audit_user", "audit_token", "audit_retired_localparts"} {
		for _, value := range []any{nil, true, int64(1), map[string]any{}} {
			cases = append(cases, struct {
				name, field string
				value       any
			}{field + "-type-" + valueName(value), field, value})
		}
		if field != "audit_retired_localparts" {
			cases = append(cases, struct {
				name, field string
				value       any
			}{field + "-array", field, []any{}})
			cases = append(cases, struct {
				name, field string
				value       any
			}{field + "-empty", field, ""})
		}
	}
	cases = append(cases, struct {
		name, field string
		value       any
	}{"retired-string", "audit_retired_localparts", "old-audit"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := auditConfigMap(t, dir)
			m[tc.field] = tc.value
			c, err := ParseConfig(auditConfigJSON(t, m))
			wantCode(t, err, configurationInvalid)
			if c.Audience != "" {
				t.Fatal("invalid returned usable config")
			}
			if _, err := ParseConfig(auditConfigJSON(t, auditConfigMap(t, dir))); err != nil {
				t.Fatal("valid control", err)
			}
		})
	}
}
func valueName(value any) string {
	if value == nil {
		return "null"
	}
	return reflect.TypeOf(value).String()
}

// All partial string subsets and a missing enabled retired list refuse; duplicate keys remain invalid under the extended strict schema.
func TestAuditConfigPresence(t *testing.T) {
	dir := tempDir(t)
	fields := []string{"audit_homeserver", "audit_room", "audit_user", "audit_token"}
	for mask := 1; mask < 15; mask++ {
		m := auditConfigMap(t, dir)
		for i, field := range fields {
			if mask&(1<<i) == 0 {
				delete(m, field)
			}
		}
		_, err := ParseConfig(auditConfigJSON(t, m))
		wantCode(t, err, configurationInvalid)
		if _, err := ParseConfig(auditConfigJSON(t, auditConfigMap(t, dir))); err != nil {
			t.Fatal(err)
		}
	}
	m := auditConfigMap(t, dir)
	delete(m, "audit_retired_localparts")
	_, err := ParseConfig(auditConfigJSON(t, m))
	wantCode(t, err, configurationInvalid)
	raw := auditConfigJSON(t, auditConfigMap(t, dir))
	for _, field := range append(fields, "audit_retired_localparts") {
		duplicate := append([]byte(`{"`+field+`":null,`), raw[1:]...)
		_, err := ParseConfig(duplicate)
		wantCode(t, err, configurationInvalid)
		if _, err := ParseConfig(raw); err != nil {
			t.Fatal(err)
		}
	}
	// Profile off with no retirement history accepts absence or an empty list; a retained list does not enable it.
	for _, retired := range []any{nil, []any{}, []any{"old-audit", "host-a_old_audit"}} {
		m := auditConfigMap(t, dir)
		for _, field := range fields {
			delete(m, field)
		}
		delete(m, "audit_retired_localparts")
		if retired != nil {
			m["audit_retired_localparts"] = retired
		}
		c, err := ParseConfig(auditConfigJSON(t, m))
		if err != nil || c.AuditUser != "" {
			t.Fatal("off control", err)
		}
	}
}

// Exact server spellings and the first-colon split preserve IPv6/ports; transport origin is independent of audience.
func TestAuditConfigExactComponents(t *testing.T) {
	for _, server := range []string{"example.org", "EXAMPLE.org.", "example.org:8448", "[2001:db8::1]:8448"} {
		m := auditConfigMap(t, tempDir(t))
		m["audience"] = server
		m["audit_user"] = "@-h_project_role:" + server
		m["audit_room"] = "!audit:" + server
		m["audit_homeserver"] = "https://[2001:db8::2]:65535"
		m["audit_retired_localparts"] = []any{"old-audit", "-h_old_audit"}
		c, err := ParseConfig(auditConfigJSON(t, m))
		if err != nil || c.AuditLocalpart != "-h_project_role" || c.AuditServer != server || len(c.AuditRetiredLocalparts) != 2 {
			t.Fatal("exact components", err)
		}
	}
}

// Startup rejects unsafe token custody/content using real temporary files; valid byte limits load without trimming or repair.
func TestAuditTokenStartup(t *testing.T) {
	for _, kind := range []string{"mode", "symlink", "directory", "missing", "empty", "space", "newline", "tab", "control", "del", "non-ascii", "oversize", "nonregular", "fifo", "file-setuid", "directory-setgid"} {
		t.Run(kind, func(t *testing.T) {
			dir := tempDir(t)
			m := auditConfigMap(t, dir)
			path := m["audit_token"].(string)
			write(t, path, []byte("fixture-token"), 0600)
			switch kind {
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(path, path+".link"); err != nil {
					t.Fatal(err)
				}
				m["audit_token"] = path + ".link"
			case "directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "file-setuid":
				if err := os.Chmod(path, 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			case "directory-setgid":
				if err := os.Chmod(dir, 0700|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "nonregular":
				m["audit_token"] = dir
			default:
				content := map[string]string{"empty": "", "space": "token value", "newline": "token\n", "tab": "token\t", "control": "\x1f", "del": "\x7f", "non-ascii": "é", "oversize": strings.Repeat("x", 4097)}[kind]
				write(t, path, []byte(content), 0600)
			}
			configPath := filepath.Join(dir, "config")
			write(t, configPath, auditConfigJSON(t, m), 0444)
			write(t, filepath.Join(dir, "allowed"), []byte("fixture"), 0444)
			before, statErr := os.Lstat(path)
			var beforeRaw []byte
			if statErr == nil && before.Mode().IsRegular() {
				beforeRaw, statErr = os.ReadFile(path)
				if statErr != nil {
					t.Fatal(statErr)
				}
			}
			c, err := loadConfig(configPath, rootFixture)
			wantCode(t, err, configurationInvalid)
			if err.Error() != "configuration_invalid" || c.Audience != "" {
				t.Fatal("unsafe diagnostics or config")
			}
			if before != nil && before.Mode().IsRegular() {
				after, err := os.Lstat(path)
				if err != nil || before.Mode() != after.Mode() {
					t.Fatal("rejection repaired metadata")
				}
				afterRaw, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(beforeRaw, afterRaw) {
					t.Fatal("rejection changed token bytes")
				}
			}
			control := tempDir(t)
			good := auditConfigMap(t, control)
			write(t, filepath.Join(control, "token"), []byte("fixture-token"), 0600)
			write(t, filepath.Join(control, "config"), auditConfigJSON(t, good), 0444)
			write(t, filepath.Join(control, "allowed"), []byte("fixture"), 0444)
			if _, err := loadConfig(filepath.Join(control, "config"), rootFixture); err != nil {
				t.Fatal("load control", err)
			}
		})
	}
	for _, token := range []string{"!", strings.Repeat("~", 4096)} {
		dir := tempDir(t)
		path := filepath.Join(dir, "token")
		write(t, path, []byte(token), 0600)
		raw, err := loadAuditToken(path, privateFile)
		if err != nil || string(raw) != token {
			t.Fatal("token byte control", err)
		}
	}
}

// Wrong-owner metadata from an opened fixture descriptor is refused; this unprivileged test does not claim a real chown.
func TestAuditTokenWrongOwner(t *testing.T) {
	dir := tempDir(t)
	path := filepath.Join(dir, "token")
	write(t, path, []byte("fixture-token"), 0600)
	_, err := loadAuditToken(path, func(info os.FileInfo) bool {
		return privateFile(ownedInfo{info, uint32(os.Geteuid() + 1), info.Mode()})
	})
	wantCode(t, err, configurationInvalid)
	if _, err := loadAuditToken(path, privateFile); err != nil {
		t.Fatal("owner control", err)
	}
}

// Retired entries obey the same validation with the profile disabled; absence alone cannot attest retirement history.
func TestAuditConfigRetiredDisabled(t *testing.T) {
	for _, list := range []any{nil, "old-audit", []any{"old-audit", "old-audit"}, []any{"@old-audit:example.org"}, []any{"Old-audit"}, []any{strings.Repeat("a", 243)}} {
		m := auditConfigMap(t, tempDir(t))
		for _, field := range []string{"audit_homeserver", "audit_room", "audit_user", "audit_token"} {
			delete(m, field)
		}
		m["audit_retired_localparts"] = list
		_, err := ParseConfig(auditConfigJSON(t, m))
		wantCode(t, err, configurationInvalid)
		m["audit_retired_localparts"] = []any{"old-audit"}
		c, err := ParseConfig(auditConfigJSON(t, m))
		if err != nil || c.AuditUser != "" || len(c.AuditRetiredLocalparts) != 1 {
			t.Fatal("disabled retained-list control", err)
		}
	}
}

// The configured audience fixes the exact mxid byte boundary for current and retired names, independent of the transport origin.
func TestAuditConfigNameLength(t *testing.T) {
	for _, field := range []string{"audit_user", "audit_retired_localparts"} {
		m := auditConfigMap(t, tempDir(t))
		set := func(local string) {
			if field == "audit_user" {
				m[field] = "@" + local + ":example.org"
			} else {
				m[field] = []any{local}
			}
		}
		set(strings.Repeat("a", 243))
		_, err := ParseConfig(auditConfigJSON(t, m))
		wantCode(t, err, configurationInvalid)
		set(strings.Repeat("a", 242))
		if _, err := ParseConfig(auditConfigJSON(t, m)); err != nil {
			t.Fatal("mxid boundary control", err)
		}
	}
}

// HTTPS scheme matching is case insensitive; authority case, trailing dots and port spelling remain byte-preserved.
func TestAuditConfigOriginSpelling(t *testing.T) {
	for _, origin := range []string{"HTTPS://Example.ORG.:00443", "https://[2001:db8::1]", "https://127.0.0.1:1"} {
		m := auditConfigMap(t, tempDir(t))
		m["audit_homeserver"] = origin
		c, err := ParseConfig(auditConfigJSON(t, m))
		if err != nil || c.AuditHomeserver != origin {
			t.Fatal("origin spelling control", err)
		}
	}
}
