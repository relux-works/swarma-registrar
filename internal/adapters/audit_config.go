package adapters

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-registrar/internal/registration"
)

// parseAuditConfig performs only local validation, preserving every spelling.
// Retirement history is operator-protected; absence while disabled cannot prove
// there were no retired accounts (§11.2). No network access occurs here.
func parseAuditConfig(obj map[string]any, c *Config) bool {
	count := 0
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"audit_homeserver", &c.AuditHomeserver}, {"audit_room", &c.AuditRoom},
		{"audit_user", &c.AuditUser}, {"audit_token", &c.AuditToken},
	} {
		if value, present := obj[field.name]; present {
			s, ok := value.(string)
			if !ok || s == "" {
				return false
			}
			*field.target = s
			count++
		}
	}
	if count != 0 && count != 4 {
		return false
	}
	if count == 4 {
		if !auditOrigin(c.AuditHomeserver) || !absolute(c.AuditToken) {
			return false
		}
		local, server, ok := strings.Cut(strings.TrimPrefix(c.AuditUser, "@"), ":")
		if !strings.HasPrefix(c.AuditUser, "@") || !ok || server != c.Audience || !serverName(server) || !auditLocalpart(local, c.Audience) {
			return false
		}
		c.AuditLocalpart, c.AuditServer = local, server
		opaque, roomServer, ok := strings.Cut(strings.TrimPrefix(c.AuditRoom, "!"), ":")
		if !strings.HasPrefix(c.AuditRoom, "!") || !ok || opaque == "" || !serverName(roomServer) || roomServer != server {
			return false
		}
	}
	value, present := obj["audit_retired_localparts"]
	if !present {
		return count == 0
	}
	list, ok := value.([]any)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	c.AuditRetiredLocalparts = make([]string, 0, len(list))
	for _, value := range list {
		local, ok := value.(string)
		if !ok || !auditLocalpart(local, c.Audience) || seen[local] || local == c.AuditLocalpart {
			return false
		}
		seen[local] = true
		c.AuditRetiredLocalparts = append(c.AuditRetiredLocalparts, local)
	}
	return true
}
func auditLocalpart(local, audience string) bool {
	return (&registration.Body{Name: local}).CheckName(audience) == nil
}

// The literal suffix is an authority only: serverName rejects URL delimiters,
// escapes, whitespace and non-ASCII. Do not parse/re-serialize a URL and thereby
// normalize the protected spelling or discard empty query/fragment delimiters.
func auditOrigin(origin string) bool {
	scheme, authority, ok := strings.Cut(origin, "://")
	if !ok || !strings.EqualFold(scheme, "https") {
		return false
	}
	if !serverName(authority) {
		return false
	}
	if colon := strings.LastIndexByte(authority, ':'); colon >= 0 && !strings.HasSuffix(authority, "]") {
		port, err := strconv.Atoi(authority[colon+1:])
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	return true
}

// The file guard runs on f.Stat, never on path metadata. Production uses
// privateFile; the test seam permits a wrong-owner witness without privileges.
func loadAuditToken(path string, guard func(os.FileInfo) bool) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, failure(configurationInvalid) }
	if !absolute(path) {
		return bad()
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || directory.Mode() != os.ModeDir|0700 {
		return bad()
	}
	stat, ok := directory.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return bad()
	}
	f, err := nofollow(path, syscall.O_RDONLY, 0)
	if err != nil {
		return bad()
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Mode() != 0600 || !guard(info) {
		return bad()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) < 1 || len(raw) > 4096 {
		return bad()
	}
	for _, b := range raw {
		if b < 0x21 || b > 0x7e {
			return bad()
		}
	}
	return raw, nil
}
