package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
)

func seed(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
func public(b byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(seed(b).Public().(ed25519.PublicKey))
}
func body() map[string]any {
	return map[string]any{"type": "enrollment/1", "host": "host-a", "keys": []any{map[string]any{"key": public(2), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": "host-a_", "explicit": []any{"legacy.dev"}}, "seq": int64(1), "state": "active", "uid_map": []any{map[string]any{"uid": int64(1), "names": []any{"host-a_project_role", "legacy.dev"}, "exe": "/usr/bin/client"}}}
}
func wire(t *testing.T, b map[string]any, publisher byte) []byte {
	t.Helper()
	pre, id, err := envelope.SigningInput(envelope.Enrollment, b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ccj.Marshal(map[string]any{"body": b, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(seed(publisher), pre))}, refusal.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func policy(t *testing.T) *Policy {
	t.Helper()
	p, err := NewPolicy("example.org", public(1), map[string]bool{"host-a": true, "host-b": false, "-node": true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Enrollment schema refuses invalid nested contracts; every case has a valid signed-record control.
func TestEnrollmentSchema(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
		code refusal.Code
	}{
		{"reserved null", func(b map[string]any) { b["sigs"] = nil }, refusal.EnrollmentSigsUnsupported},
		{"reserved empty", func(b map[string]any) { b["sigs"] = []any{}; b["type"] = false }, refusal.EnrollmentSigsUnsupported},
		{"unknown", func(b map[string]any) { b["extra"] = true }, refusal.EnrollmentMalformed},
		{"type", func(b map[string]any) { b["type"] = "registration/1" }, refusal.EnrollmentMalformed},
		{"host", func(b map[string]any) { b["host"] = "Host_A" }, refusal.EnrollmentMalformed},
		{"host length", func(b map[string]any) { b["host"] = strings.Repeat("a", 33) }, refusal.EnrollmentMalformed},
		{"classification", func(b map[string]any) { b["host"] = "unconfigured" }, refusal.RegistryUnavailable},
		{"no keys", func(b map[string]any) { b["keys"] = []any{} }, refusal.EnrollmentMalformed},
		{"key point", func(b map[string]any) {
			b["keys"].([]any)[0].(map[string]any)["key"] = "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}, refusal.EnrollmentMalformed},
		{"key nested extra", func(b map[string]any) { b["keys"].([]any)[0].(map[string]any)["extra"] = true }, refusal.EnrollmentMalformed},
		{"key duplicate", func(b map[string]any) { k := b["keys"].([]any)[0]; b["keys"] = []any{k, k} }, refusal.EnrollmentMalformed},
		{"timestamp", func(b map[string]any) { b["keys"].([]any)[0].(map[string]any)["not_before"] = "2024-02-30T00:00:00Z" }, refusal.EnrollmentMalformed},
		{"empty interval", func(b map[string]any) { b["keys"].([]any)[0].(map[string]any)["not_after"] = "2024-01-01T00:00:00Z" }, refusal.EnrollmentMalformed},
		{"prefix", func(b map[string]any) { b["names"].(map[string]any)["prefix"] = "host-b_" }, refusal.EnrollmentMalformed},
		{"explicit syntax", func(b map[string]any) { b["names"].(map[string]any)["explicit"] = []any{"Upper"} }, refusal.EnrollmentMalformed},
		{"explicit structured-only", func(b map[string]any) { b["names"].(map[string]any)["explicit"] = []any{"-node_p_r"} }, refusal.EnrollmentMalformed},
		{"explicit duplicate", func(b map[string]any) { b["names"].(map[string]any)["explicit"] = []any{"legacy.dev", "legacy.dev"} }, refusal.EnrollmentMalformed},
		{"seq zero", func(b map[string]any) { b["seq"] = int64(0) }, refusal.EnrollmentMalformed},
		{"seq string", func(b map[string]any) { b["seq"] = "1" }, refusal.EnrollmentMalformed},
		{"state", func(b map[string]any) { b["state"] = "disabled" }, refusal.EnrollmentMalformed},
		{"station map missing", func(b map[string]any) { delete(b, "uid_map") }, refusal.EnrollmentMalformed},
		{"map empty", func(b map[string]any) { b["uid_map"] = []any{} }, refusal.EnrollmentMalformed},
		{"uid zero", func(b map[string]any) { b["uid_map"].([]any)[0].(map[string]any)["uid"] = int64(0) }, refusal.EnrollmentMalformed},
		{"uid sentinel", func(b map[string]any) { b["uid_map"].([]any)[0].(map[string]any)["uid"] = int64(4294967295) }, refusal.EnrollmentMalformed},
		{"uid string", func(b map[string]any) { b["uid_map"].([]any)[0].(map[string]any)["uid"] = "1" }, refusal.EnrollmentMalformed},
		{"uid duplicate", func(b map[string]any) { u := b["uid_map"].([]any)[0]; b["uid_map"] = []any{u, u} }, refusal.EnrollmentMalformed},
		{"uid unknown", func(b map[string]any) { b["uid_map"].([]any)[0].(map[string]any)["extra"] = true }, refusal.EnrollmentMalformed},
		{"name wrong authority", func(b map[string]any) {
			b["uid_map"].([]any)[0].(map[string]any)["names"] = []any{"host-b_project_role"}
		}, refusal.EnrollmentMalformed},
		{"name duplicate", func(b map[string]any) {
			b["uid_map"].([]any)[0].(map[string]any)["names"] = []any{"legacy.dev", "legacy.dev"}
		}, refusal.EnrollmentMalformed},
		{"name shared", func(b map[string]any) {
			b["uid_map"] = []any{map[string]any{"uid": int64(1), "names": []any{"legacy.dev"}}, map[string]any{"uid": int64(2), "names": []any{"legacy.dev"}}}
		}, refusal.EnrollmentMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := policy(t)
			b := body()
			tc.edit(b)
			if _, err := p.Parse(wire(t, b, 1)); !refusal.Is(err, tc.code) {
				t.Fatalf("got %v", err)
			}
			if _, err := p.Parse(wire(t, body(), 1)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, field := range []string{"type", "host", "keys", "names", "seq", "state"} {
		b := body()
		delete(b, field)
		if _, err := policy(t).Parse(wire(t, b, 1)); !refusal.Is(err, refusal.EnrollmentMalformed) {
			t.Fatal(err)
		}
	}
}

// Executable paths are literal portable absolute paths; invalid components/controls are never normalized.
func TestExecutablePaths(t *testing.T) {
	for _, path := range []string{"", "/", "bin/client", "/usr//client", "/usr/./client", "/usr/../client", "/usr/client/", "/usr\\client", "/a\x00b", "/a\x7fb", strings.Repeat("/x", 2049)} {
		b := body()
		b["uid_map"].([]any)[0].(map[string]any)["exe"] = path
		if _, err := policy(t).Parse(wire(t, b, 1)); !refusal.Is(err, refusal.EnrollmentMalformed) {
			t.Fatalf("%q: %v", path, err)
		}
	}
	for _, path := range []string{"/bin/client", "/é/client", "/" + strings.Repeat("a", 4095)} {
		b := body()
		b["uid_map"].([]any)[0].(map[string]any)["exe"] = path
		if _, err := policy(t).Parse(wire(t, b, 1)); err != nil {
			t.Fatal(err)
		}
	}
}

// Only the pinned Ed25519 publisher verifies; host signatures and other publisher keys cannot confer enrollment authority.
func TestPublisherAndPhases(t *testing.T) {
	p := policy(t)
	for _, signer := range []byte{2, 3} {
		if _, err := p.Parse(wire(t, body(), signer)); !refusal.Is(err, refusal.EnrollmentSignatureInvalid) {
			t.Fatal(err)
		}
	}
	raw := wire(t, body(), 1)
	changed := bytes.Clone(raw)
	index := bytes.Index(changed, []byte("sha256:")) + 7
	changed[index] = '0'
	if bytes.Equal(changed, raw) {
		changed[index] = '1'
	}
	if _, err := p.Parse(changed); !refusal.Is(err, refusal.EnrollmentIDMismatch) {
		t.Fatal(err)
	}
	if _, err := p.Parse(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPolicy("example.org", public(2), nil); err != nil {
		t.Fatal(err)
	}
	curve := elliptic.P256()
	validP256 := "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(curve, curve.Params().Gx, curve.Params().Gy))
	if _, err := NewPolicy("example.org", validP256, nil); !refusal.Is(err, refusal.RegistryUnavailable) {
		t.Fatal(err)
	}
	if _, err := NewPolicy("example.org", "p256:AA", nil); !refusal.Is(err, refusal.RegistryUnavailable) {
		t.Fatal(err)
	}
}

// Boundary/nonstation records validate, key windows are half-open, and only exact owned names are permitted.
func TestEnrollmentPositiveBoundariesAndNames(t *testing.T) {
	p := policy(t)
	b := body()
	b["seq"] = int64(9007199254740991)
	b["uid_map"].([]any)[0].(map[string]any)["uid"] = int64(4294967294)
	r, err := p.Parse(wire(t, b, 1))
	if err != nil {
		t.Fatal(err)
	}
	k := r.Keys[0]
	if !k.ValidAt(k.NotBefore, k.NotAfter-1) {
		t.Fatal("half-open interior")
	}
	if k.ValidAt(k.NotBefore-1, k.NotBefore) || k.ValidAt(k.NotBefore, k.NotAfter) || k.ValidAt(k.NotAfter, k.NotBefore) || k.ValidAt(k.NotBefore, k.NotBefore-1) {
		t.Fatal("half-open boundary")
	}
	for _, name := range []string{"host-a_project_role", "host-a_project_role-q", "legacy.dev"} {
		if err := r.Permits(name, "example.org"); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"host-a_project_role_extra", "host-b_project_role", "legacy.dew"} {
		if !refusal.Is(r.Permits(name, "example.org"), refusal.NameNotPermitted) {
			t.Fatal(name)
		}
	}
	if !refusal.Is(r.Permits("Upper", "example.org"), refusal.NameInvalid) {
		t.Fatal("syntax")
	}
	b = body()
	b["host"] = "host-b"
	b["names"].(map[string]any)["prefix"] = "host-b_"
	delete(b, "uid_map")
	if _, err := p.Parse(wire(t, b, 1)); err != nil {
		t.Fatal(err)
	}
	b = body()
	b["host"] = "-node"
	b["names"].(map[string]any)["prefix"] = "-node_"
	b["uid_map"].([]any)[0].(map[string]any)["names"] = []any{"-node_project_role"}
	r, err = p.Parse(wire(t, b, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Permits("-node_project_role", "example.org"); err != nil {
		t.Fatal(err)
	}
	clone := r.Clone()
	clone.UIDMap[0].Names[0] = "changed"
	clone.Keys = nil
	if r.UIDMap[0].Names[0] != "-node_project_role" || len(r.Keys) != 1 {
		t.Fatal("alias")
	}
}

// Each collection cap is inclusive; distinct overlapping keys and maximum UID/name counts remain legal.
func TestEnrollmentCollectionLimits(t *testing.T) {
	for _, field := range []string{"keys", "explicit", "uid_map", "uid_names"} {
		t.Run(field, func(t *testing.T) {
			for _, excess := range []bool{true, false} {
				b := body()
				limit := 256
				if field == "keys" {
					limit = 16
				}
				if field == "uid_names" {
					limit = 64
				}
				count := limit
				if excess {
					count++
				}
				items := make([]any, count)
				for i := range items {
					switch field {
					case "keys":
						items[i] = map[string]any{"key": public(byte(i + 2)), "not_before": "2024-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z"}
					case "explicit":
						items[i] = fmt.Sprintf("legacy.%03d", i)
					case "uid_map":
						items[i] = map[string]any{"uid": int64(i + 1), "names": []any{fmt.Sprintf("host-a_project_r%d", i)}}
					case "uid_names":
						items[i] = fmt.Sprintf("host-a_project_r%d", i)
					}
				}
				switch field {
				case "keys":
					b["keys"] = items
				case "explicit":
					b["names"].(map[string]any)["explicit"] = items
					b["uid_map"].([]any)[0].(map[string]any)["names"] = []any{"host-a_project_role"}
				case "uid_map":
					b["uid_map"] = items
				case "uid_names":
					b["uid_map"].([]any)[0].(map[string]any)["names"] = items
				}
				_, err := policy(t).Parse(wire(t, b, 1))
				if excess {
					if !refusal.Is(err, refusal.EnrollmentMalformed) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	c := elliptic.P256()
	b := body()
	b["keys"].([]any)[0].(map[string]any)["key"] = "p256:" + base64.RawURLEncoding.EncodeToString(elliptic.MarshalCompressed(c, c.Params().Gx, c.Params().Gy))
	if _, err := policy(t).Parse(wire(t, b, 1)); err != nil {
		t.Fatal(err)
	}
}
