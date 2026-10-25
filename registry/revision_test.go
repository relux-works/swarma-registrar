package registry_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/registry"
)

// The public wrapper forwards the protected profile: both own-format IDs
// publish, while the other profile, missing and unknown pins publish nothing.
func TestLoaderObjectFormat(t *testing.T) {
	policy, err := enrollment.NewPolicy("example.org", queryPublic(1), map[string]bool{"host-a": true})
	if err != nil {
		t.Fatal(err)
	}
	entries := []registry.Entry{queryEntry(t, "enrollments/a.json", 1, 2, "active")}
	for _, profile := range []struct {
		format string
		width  int
	}{{"sha1", 40}, {"sha256", 64}} {
		revision := strings.Repeat("a", profile.width)
		for _, selected := range []string{"sha1", "sha256", "", "sha512"} {
			store := &fixtureStore{}
			loader := registry.Loader{ObjectFormat: selected, Policy: policy, Verifier: fixtureVerifier{revision, entries}, Store: store}
			snapshot, next, err := loader.Load(registry.Input{Revision: revision, Entries: entries, FirstUse: true})
			if selected == profile.format {
				if err != nil || snapshot == nil || next == nil || snapshot.Revision() != revision {
					t.Fatalf("own-format control: %v", err)
				}
			} else {
				var refusal *registry.Error
				if !errors.As(err, &refusal) || refusal.Code != registry.RegistryUnavailable || snapshot != nil || next != nil || store.state != nil {
					t.Fatalf("invalid profile returned authority: %v", err)
				}
			}
		}
	}
}
