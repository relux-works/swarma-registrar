package registry

import (
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/refusal"
)

// Each protected profile accepts only its own exact lowercase object IDs, in
// both candidate and retained state. Refusals precede verification/persistence
// and preserve retained and durable state; the adjacent valid reload still works.
func TestProtectedRevisionFormat(t *testing.T) {
	for _, profile := range []struct {
		format      string
		size, other int
	}{{"sha1", 40, 64}, {"sha256", 64, 40}} {
		t.Run(profile.format, func(t *testing.T) {
			valid := strings.Repeat("a", profile.size)
			cases := []struct{ name, revision string }{
				{"other-format", strings.Repeat("a", profile.other)},
				{"one-short", strings.Repeat("a", profile.size-1)},
				{"one-long", strings.Repeat("a", profile.size+1)},
				{"uppercase", strings.ToUpper(valid)},
				{"short", "abcdef1"}, {"branch", "main"}, {"empty", ""},
				{"non-hex", valid[:len(valid)-1] + "g"},
				{"newline", valid + "\n"},
			}
			for _, target := range []string{"candidate", "retained"} {
				for _, tc := range cases {
					t.Run(target+"/"+tc.name, func(t *testing.T) {
						l, v, s := loader(t)
						l.ObjectFormat = profile.format
						entries := []Entry{entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)}
						initial, retained, err := l.Load(Input{Revision: valid, Entries: entries, FirstUse: true})
						if err != nil || initial == nil || retained == nil || s.calls != 1 {
							t.Fatalf("valid bootstrap: %v", err)
						}
						in := Input{Revision: valid, Entries: entries, Retained: retained.Clone(), Reconciled: true}
						if target == "candidate" {
							in.Revision = tc.revision
						} else {
							in.Retained.Revision = tc.revision
						}
						before := s.state.Clone()
						v.seen = nil
						verdict(t, l, in, refusal.RegistryUnavailable, "")
						if len(v.seen) != 0 || v.ancestryCalls != 0 || s.calls != 1 || !reflect.DeepEqual(before, s.state) {
							t.Fatal("refusal had verification or persistence effects")
						}
						if initial.Revision() != valid {
							t.Fatal("prior snapshot changed")
						}
						accepted, next, err := l.Load(Input{Revision: valid, Entries: entries, Retained: retained, Reconciled: true})
						if err != nil || accepted == nil || next == nil || next.Revision != valid || s.calls != 2 {
							t.Fatalf("valid reload: %v", err)
						}
					})
				}
			}
		})
	}
}

// A missing, differently cased or unknown profile never selects an algorithm
// from a valid-looking supplied ID; both supported profiles remain usable.
func TestMissingOrUnknownObjectFormatRefused(t *testing.T) {
	for _, format := range []string{"", "SHA1", "sha512", "sha1|sha256"} {
		for _, size := range []int{40, 64} {
			l, v, s := loader(t)
			l.ObjectFormat = format
			entries := []Entry{entry(t, "enrollments/a.json", record("host-a", 1, 2, "active"), 1)}
			verdict(t, l, Input{Revision: strings.Repeat("a", size), Entries: entries, FirstUse: true}, refusal.RegistryUnavailable, "")
			if len(v.seen) != 0 || s.calls != 0 || s.state != nil {
				t.Fatal("invalid profile reached verifier/store")
			}
			if size == 40 {
				l.ObjectFormat = "sha1"
			} else {
				l.ObjectFormat = "sha256"
			}
			if snapshot, next, err := l.Load(Input{Revision: strings.Repeat("a", size), Entries: entries, FirstUse: true}); err != nil || snapshot == nil || next == nil {
				t.Fatalf("valid profile control: %v", err)
			}
		}
	}
}
