package adapters

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/audittest"
)

// Removing the token file after startup cannot affect the retained client or
// trigger a reload in recovery; the disabled profile never obtains a reservation.
func TestAuditStartupTokenAndDisabledProfile(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			hs := audittest.New(t)
			cfg := hs.Config(filepath.Join(dir, "unused"))
			c := Config{AuditFile: filepath.Join(dir, "audit"), ObjectFormat: "sha1"}
			if enabled {
				c.AuditHomeserver, c.AuditUser, c.AuditRoom, c.AuditToken = cfg.Origin, cfg.User, cfg.Room, filepath.Join(dir, "token")
				if err := os.WriteFile(c.AuditToken, []byte(audittest.Token), 0600); err != nil {
					t.Fatal(err)
				}
			}
			a, err := openAudit(context.Background(), c, cfg.Roots)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if enabled {
				if err = os.Remove(c.AuditToken); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5e9)
			defer cancel()
			_, done, err := a.BeginIssue(ctx)
			if enabled {
				if err != nil {
					t.Fatal("token was reloaded after startup")
				}
				done()
			} else if err == nil {
				done()
				t.Fatal("disabled profile opened issuance")
			}
		})
	}
}
