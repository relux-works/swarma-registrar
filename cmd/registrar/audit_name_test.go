package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

// Command wiring preserves current and disabled-profile retired exclusions; a neighbouring configured identity permits the enrolled proof with a test sink.
func TestAuditNameWiring(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current string
		retired []string
		status  int
		code    string
	}{
		{"current", "host-a_project_role", nil, 403, "name_not_permitted"},
		{"retired-off", "", []string{"host-a_project_role"}, 403, "name_not_permitted"},
		{"current-neighbor", "host-a_project_rolf", nil, 200, ""},
		{"retired-neighbor", "", []string{"host-a_project_rolf"}, 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			f.config.AuditLocalpart = tc.current
			if tc.current != "" {
				f.config.AuditServer = f.config.Audience
			}
			f.config.AuditRetiredLocalparts = tc.retired
			url, client := startTestServer(t, testDependencies(t, f, false, false), true, true)
			response, err := client.Post(url+"/v1/registration", "application/json", bytes.NewReader(proof(t)))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			raw, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			var result struct{ JWT, Code string }
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || result.Code != tc.code || (result.JWT != "") != (tc.status == 200) {
				t.Fatalf("status/code/JWT: %d/%s/%t", response.StatusCode, result.Code, result.JWT != "")
			}
		})
	}
}
