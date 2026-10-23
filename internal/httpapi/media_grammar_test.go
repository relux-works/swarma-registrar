package httpapi

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Quoted charset and whitespace outside §6's SP/HTAB boundaries are 415
// refusals with no JWT and null audit identity. Same-pair success at capacity
// one proves these early refusals debit neither budget nor reserve the nonce.
func TestMediaGrammarRefusals(t *testing.T) {
	cases := []struct{ name, header string }{
		{"quoted-lower", `application/json;charset="utf-8"`},
		{"quoted-upper", `APPLICATION/JSON;CHARSET="UTF-8"`},
		{"quoted-mixed-ows", " \tApplication/Json \t; \tCharSet=\"UtF-8\"\t "},
		{"equals-left-space", "application/json;charset =utf-8"},
		{"equals-left-tab", "application/json;charset\t=utf-8"},
		{"equals-right-space", "application/json;charset= utf-8"},
		{"equals-right-tab", "application/json;charset=\tutf-8"},
		{"equals-both", "application/json;charset = utf-8"},
		{"type-space", "appli cation/json"},
		{"type-tab", "appli\tcation/json"},
		{"slash-left-space", "application /json"},
		{"slash-right-tab", "application/\tjson"},
		{"subtype-space", "application/js on"},
		{"subtype-tab", "application/js\ton"},
		{"name-space", "application/json;char set=utf-8"},
		{"name-tab", "application/json;char\tset=utf-8"},
		{"value-space", "application/json;charset=utf -8"},
		{"value-tab", "application/json;charset=utf-\t8"},
		{"field-vtab", "\vapplication/json"},
		{"field-formfeed", "application/json\f"},
		{"semicolon-newline", "application/json;\ncharset=utf-8"},
		{"non-ascii-media", "application/jſon"},
		{"non-ascii-name", "application/json;charſet=utf-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			raw := validProof(t, 1)
			req := request(raw)
			req.Header.Set("Content-Type", tc.header)
			rejected(t, serve(t, f, req), "unsupported_media_type", 415)
			unverifiedAudit(t, f, "unsupported_media_type", len(raw))
			if event := f.audit.events(t)[0]; event["http_status"] != float64(415) {
				t.Fatal(event)
			}
			accepted(t, f, raw)
		})
	}
}

// OWS at the complete field and either side of the semicolon is permitted,
// independently of case; the existing exact JWT/audit oracle checks success.
func TestMediaGrammarOWS(t *testing.T) {
	cases := []struct{ name, header string }{
		{"bare", "application/json"},
		{"unquoted", "application/json;charset=utf-8"},
		{"field-no-parameter", " \tAPPLICATION/JSON\t "},
		{"semicolon-before-space", "application/json ;charset=utf-8"},
		{"semicolon-after-tab", "application/json;\tcharset=utf-8"},
		{"semicolon-both", "application/json \t; \tcharset=utf-8"},
		{"field-with-parameter", "\t application/json;charset=utf-8 \t"},
		{"combined-case", " \tApplication/Json\t ; \tChArSeT=UtF-8\t "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			raw := validProof(t, 1)
			req := request(raw)
			req.Header.Set("Content-Type", tc.header)
			w := serve(t, f, req)
			if w.Code != 200 {
				t.Fatalf("OWS control: %d %s", w.Code, w.Body)
			}
			want, _ := json.Marshal(map[string]string{"jwt": expectedJWT(t, raw)})
			if !bytes.Equal(w.Body.Bytes(), want) {
				t.Fatalf("JWT response: %s", w.Body)
			}
			events := f.audit.events(t)
			if len(events) != 1 || events[0]["outcome"] != "issued" || events[0]["http_status"] != float64(200) || len(f.audit.acks) != 1 || !bytes.Equal(f.audit.lines[0], f.audit.acks[0]) {
				t.Fatal("issued audit/ack mismatch")
			}

		})
	}
}
