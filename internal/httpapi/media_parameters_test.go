package httpapi

import "testing"

// Raw unsupported parameter names must not disappear during MIME normalization.
// Every refusal has null audit identity and leaves the same signed proof usable
// at capacity one, proving neither budget nor nonce was consumed. No header here
// depends on surrounding whitespace or quoted charset interpretation.
func TestMediaRawParameterNames(t *testing.T) {
	cases := []struct{ name, header string }{
		{"orphan boundary continuation", "application/json;boundary*1=unexpected"},
		{"orphan encoded boundary continuation", "application/json;boundary*2*=utf-8''unexpected"},
		{"undecodable boundary extension", "application/json;boundary*=bogus''unexpected"},
		{"orphan charset continuation", "application/json;charset*1=latin1"},
		{"malformed extended charset value", "application/json;charset*=utf-8''%ZZ"},
		{"decodable extended charset", "application/json;charset*=utf-8''utf-8"},
		{"initial charset continuation", "application/json;charset*0=utf-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t) // One attempt per key/name makes an early debit observable.
			raw := validProof(t, 1)
			r := request(raw)
			r.Header.Set("Content-Type", tc.header)
			rejected(t, serve(t, f, r), "unsupported_media_type", 415)
			unverifiedAudit(t, f, "unsupported_media_type", len(raw))
			if event := f.audit.events(t)[0]; event["http_status"] != float64(415) {
				t.Fatal(event)
			}
			accepted(t, f, raw)
		})
	}
}
