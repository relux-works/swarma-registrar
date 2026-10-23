package conformance_test

import (
	"encoding/json"
	"testing"
)

// These Appendix B rules must be reached through successful signed HTTP prefixes
// from empty accounting, not skipped or seeded through private fields. Literal
// outcomes below are grounded in each row's rule, independent of generated codes.
func TestReachableAccountingTraces(t *testing.T) {
	cases := []struct {
		row, code string
		prefixes  int
	}{
		{"R83", "nonce_replayed", 1}, {"R84", "nonce_replayed", 1},
		{"R86", "rate_limited", 10}, {"R87", "rate_limited", 3},
		{"R111", "rate_limited", 3}, {"R129", "rate_limited", 1},
		{"PR13", "accept", 10}, {"PR14", "accept", 2}, {"PR18", "accept", 1},
	}
	for _, tc := range cases {
		t.Run(tc.row, func(t *testing.T) {
			v := reviewerVector(t, tc.row)
			if reason := admissionPending(v); reason != "" {
				t.Errorf("reachable row still pending: %s", reason)
			}
			if v.Expected.Code != tc.code || len(v.Before) != tc.prefixes || len(v.Fixture.NonceCache) != 0 || len(v.Fixture.LimiterEvents) != 0 {
				t.Fatal("rule outcome or declared empty-accounting prefix changed")
			}
			for _, step := range v.Before {
				if step.Event != "request" || step.Expected.Code != "accept" {
					t.Fatal("prefix must issue legitimate proofs")
				}
			}
			if tc.row == "R83" && v.Before[0].Bytes != v.Input.Bytes {
				t.Fatal("R83 must replay identical proof bytes")
			}
			if tc.row == "R84" && v.Before[0].Bytes == v.Input.Bytes {
				t.Fatal("R84 must replay the pair under a changed body")
			}
			if tc.row == "R111" && (len(v.After) != 1 || v.After[0].Bytes != v.Input.Bytes || v.After[0].Expected.Code != "accept") {
				t.Fatal("R111 must retry unchanged fresh proof at original release time")
			}

			var main struct {
				Body struct{ Key, Name, Nonce string }
			}
			if err := json.Unmarshal(decodeExpected(t, v.Input.Bytes), &main); err != nil {
				t.Fatal(err)
			}
			names, nonces := map[string]bool{}, map[string]bool{}
			epoch := v.Fixture.Now - 60
			for i, step := range v.Before {
				var prior struct {
					Body struct{ Key, Name, Nonce string }
				}
				if err := json.Unmarshal(decodeExpected(t, step.Bytes), &prior); err != nil {
					t.Fatal(err)
				}
				wantMono := int64(1)
				if tc.row == "R83" || tc.row == "R84" || tc.row == "PR18" {
					wantMono = 60
				}
				if tc.row == "PR13" && i == 0 {
					wantMono = 0
				}
				if step.MonotonicNow == nil || *step.MonotonicNow != wantMono || step.Now != epoch+wantMono {
					t.Fatal("explicit UTC/monotonic prefix boundary changed")
				}
				if tc.row == "PR18" {
					if prior.Body.Key == main.Body.Key || prior.Body.Nonce != main.Body.Nonce || prior.Body.Name != main.Body.Name {
						t.Fatal("cross-key same-nonce/name witness lost")
					}
				} else if prior.Body.Key != main.Body.Key {
					t.Fatal("prefix must charge the tested key")
				}
				if tc.row == "R83" || tc.row == "R84" {
					if prior.Body.Nonce != main.Body.Nonce {
						t.Fatal("replay pair witness lost")
					}
				}
				if tc.row == "R84" && prior.Body.Name == main.Body.Name {
					t.Fatal("changed permitted name witness lost")
				}
				if tc.row == "R86" || tc.row == "PR13" {
					if names[prior.Body.Name] || prior.Body.Name == main.Body.Name {
						t.Fatal("distinct-name key-budget witness lost")
					}
				} else if tc.row != "R84" && prior.Body.Name != main.Body.Name {
					t.Fatal("same-name budget witness lost")
				}
				if tc.row != "R83" && tc.row != "R84" && tc.row != "PR18" {
					if nonces[prior.Body.Nonce] || prior.Body.Nonce == main.Body.Nonce {
						t.Fatal("fresh nonce witness lost")
					}
				}
				names[prior.Body.Name] = true
				nonces[prior.Body.Nonce] = true
			}
			if tc.row == "R111" {
				if v.Expected.RetryAfter == nil || *v.Expected.RetryAfter != 1 || v.After[0].Now != epoch+61 || v.After[0].MonotonicNow == nil || *v.After[0].MonotonicNow != 61 {
					t.Fatal("original release time witness lost")
				}
			}
			r := reviewerRun(t, v)
			r.establishAccounting(t, "../../vectors")
			for _, step := range v.Before {
				r.transition(t, step)
			}
			r.request(t, v.Input.Bytes, v.Fixture.Now, v.Expected, true)
			for _, step := range v.After {
				r.transition(t, step)
			}
			r.checkState(t)
		})
	}
}
