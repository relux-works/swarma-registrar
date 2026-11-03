package admission

import (
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
)

func auditNameFixture(t *testing.T, current string, retired []string) *fixture {
	t.Helper()
	f := setup(t)
	f.cfg.Registry = snapshot(t, 2, "active", epoch-100, epoch+10000, "legacy.dev", "legacy.dex", "legacy.de", "legacy.dev-extra")
	f.cfg.AuditLocalpart = current
	if current != "" {
		f.cfg.AuditServer = f.cfg.Audience
	}
	f.cfg.AuditRetiredLocalparts = retired
	var err error
	f.a, err = New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func nameProof(t *testing.T, name string, nonce byte) *registration.Body {
	t.Helper()
	return proof(t, nonce, name, "example.org", epoch+100, epoch+120)
}
func assertNameAccounting(t *testing.T, f *fixture, p *registration.Body, k, n, nonces int) {
	t.Helper()
	if len(f.a.keyEvents[p.Key.Encoding()]) != k || len(f.a.nameEvents[p.Name]) != n || len(f.a.nonces) != nonces {
		t.Fatal("nonce or budget accounting changed")
	}
	if nonces > 0 {
		pair := nonceID{key: p.Key.Encoding()}
		copy(pair.nonce[:], p.Nonce)
		if f.a.nonces[pair] != p.ExpiresAt+30 {
			t.Fatal("nonce not retained to expiry")
		}
	}
}

// Exact enrolled current/retired names refuse after reservation and both debits; siblings, strict prefixes and one-byte near misses still issue.
func TestAuditNameReservation(t *testing.T) {
	for _, tc := range []struct {
		name, current string
		retired       []string
		controls      []string
	}{
		{"legacy-current", "legacy.dev", nil, []string{"legacy.dex", "legacy.de", "legacy.dev-extra", "host-a_project_role"}},
		{"structured-current", "host-a_project_role", nil, []string{"host-a_project_rolf", "host-a_project_role-q1"}},
		{"legacy-retired-off", "", []string{"legacy.dev"}, []string{"legacy.dex", "legacy.de", "legacy.dev-extra", "host-a_project_role"}},
		{"structured-retired-off", "", []string{"host-a_project_role"}, []string{"host-a_project_rolf", "host-a_project_role-q1"}},
		{"retired-on", "host-a_new_audit", []string{"legacy.dev", "host-a_project_role"}, []string{"host-a_project_rolf"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.current
			if len(tc.retired) > 0 {
				name = tc.retired[len(tc.retired)-1]
			}
			f := auditNameFixture(t, tc.current, tc.retired)
			p := nameProof(t, name, 1)
			f.signer.hook = func() { t.Fatal("reserved name reached signer") }
			e := rejected(t, f.a, p, refusal.NameNotPermitted)
			if e.RetryAfter != 0 {
				t.Fatal("retry on reserved name")
			}
			assertNameAccounting(t, f, p, 1, 1, 1)
			events := f.audit.events()
			if len(events) != 1 || events[0]["outcome"] != "refused" || events[0]["name"] != name || events[0]["code"] != "name_not_permitted" || len(f.audit.acks) != 1 || !f.a.Ready() {
				t.Fatal("refusal audit/readiness")
			}
			rejected(t, f.a, p, refusal.NonceReplayed)
			assertNameAccounting(t, f, p, 2, 2, 1)
			rejected(t, f.a, nameProof(t, name, 2), refusal.NameNotPermitted)
			rejected(t, f.a, nameProof(t, name, 3), refusal.RateLimited)
			assertNameAccounting(t, f, p, 3, 3, 2)
			for _, neighbor := range tc.controls {
				g := auditNameFixture(t, tc.current, tc.retired)
				q := nameProof(t, neighbor, 1)
				issued(t, g.a, q)
				assertNameAccounting(t, g, q, 1, 1, 1)
				if len(g.audit.acks) != 1 || g.audit.events()[0]["outcome"] != "issued" {
					t.Fatal("control not issued")
				}
			}
		})
	}
}

// Rows 12/13/14/15/18/19 keep precedence over 19b; row 19b precedes signing availability (row 20).
func TestAuditNamePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    refusal.Code
		edit    func(*fixture) *registration.Body
		charged bool
	}{
		{"name-syntax", refusal.NameInvalid, func(f *fixture) *registration.Body { return nameProof(t, "Legacy.dev", 1) }, false},
		{"enrollment", refusal.NameNotPermitted, func(f *fixture) *registration.Body {
			f.cfg.AuditLocalpart = "other.dev"
			var err error
			f.a, err = New(f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			return nameProof(t, "other.dev", 1)
		}, false},
		{"audience", refusal.AudienceMismatch, func(f *fixture) *registration.Body {
			return proof(t, 1, "legacy.dev", "EXAMPLE.org", epoch+100, epoch+120)
		}, false},
		{"clock", refusal.ClockSkew, func(f *fixture) *registration.Body {
			f.clock.set(Reading{UTC: epoch + 100, Monotonic: 100 * time.Second, Healthy: false})
			return nameProof(t, "legacy.dev", 1)
		}, false},
		{"signing-paused", refusal.NameNotPermitted, func(f *fixture) *registration.Body { f.a.PauseSigning(); return nameProof(t, "legacy.dev", 1) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := auditNameFixture(t, "legacy.dev", nil)
			p := tc.edit(f)
			rejected(t, f.a, p, tc.code)
			count := 0
			if tc.charged {
				count = 1
			}
			assertNameAccounting(t, f, p, count, count, count)
			g := auditNameFixture(t, "legacy.dev", nil)
			issued(t, g.a, valid(t, 1))
		})
	}
	// A full name budget refuses before reservation; an existing nonce refuses before 19b (tested above).
	f := auditNameFixture(t, "legacy.dev", nil)
	for n := byte(1); n <= 3; n++ {
		rejected(t, f.a, nameProof(t, "legacy.dev", n), refusal.NameNotPermitted)
	}
	rejected(t, f.a, nameProof(t, "legacy.dev", 4), refusal.RateLimited)
	p := nameProof(t, "legacy.dev", 1)
	assertNameAccounting(t, f, p, 3, 3, 3)
	g := auditNameFixture(t, "legacy.dev", nil)
	issued(t, g.a, valid(t, 1))
}

// Constructor rejects inconsistent current components and invalid retired entries; copied retirement configuration cannot be changed after construction.
func TestAuditNameConfiguration(t *testing.T) {
	for _, edit := range []func(*Config){
		func(c *Config) { c.AuditLocalpart = "legacy.dev" },
		func(c *Config) { c.AuditServer = c.Audience },
		func(c *Config) { c.AuditLocalpart = "legacy.dev"; c.AuditServer = "EXAMPLE.org" },
		func(c *Config) { c.AuditLocalpart = "Legacy.dev"; c.AuditServer = c.Audience },
		func(c *Config) { c.AuditRetiredLocalparts = []string{"@legacy.dev:example.org"} },
		func(c *Config) { c.AuditRetiredLocalparts = []string{"legacy.dev", "legacy.dev"} },
		func(c *Config) {
			c.AuditLocalpart = "legacy.dev"
			c.AuditServer = c.Audience
			c.AuditRetiredLocalparts = []string{"legacy.dev"}
		},
	} {
		f := setup(t)
		edit(&f.cfg)
		if _, err := New(f.cfg); err == nil {
			t.Fatal("invalid reservation config accepted")
		}
		g := auditNameFixture(t, "legacy.dev", nil)
		issued(t, g.a, valid(t, 1))
	}
	retired := []string{"legacy.dev"}
	f := auditNameFixture(t, "", retired)
	retired[0] = "other.dev"
	rejected(t, f.a, nameProof(t, "legacy.dev", 1), refusal.NameNotPermitted)
	issued(t, f.a, valid(t, 2))
}
