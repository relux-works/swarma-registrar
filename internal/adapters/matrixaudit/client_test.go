package matrixaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const room = "!a/b?c# é:example.org"

var eventID = "$" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
var original = []byte("{\"seq\":1}\n")

type fixture struct {
	t                        *testing.T
	server                   *httptest.Server
	c                        *Client
	now                      time.Time
	budget                   *Budget
	puts, gets               int
	events                   map[string][]byte
	putStatus, getStatus     int
	putBody, getBody         []byte
	mutate                   func(map[string]any)
	advancePut, advanceGet   time.Duration
	duplicate                bool
	paths                    []string
	state                    []any
	stateBody                []byte
	stateStatus              int
	who                      any
	advanceWho, advanceState time.Duration
	pages                    []map[string]any
	page                     int
	filters                  []string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := setupServer(t)
	if err := f.c.startup(context.Background(), f.budget, false, func(context.Context, *Budget) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return f
}
func setupServer(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, now: time.Now(), events: map[string][]byte{}, putStatus: 200, getStatus: 200, state: validState(), stateStatus: 200, who: map[string]any{"user_id": "@audit:example.org", "device_id": "DEVICE"}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Origin: f.server.URL, Room: room, User: "@audit:example.org", BindingPath: filepath.Join(dir, "binding")}
	c, err := newTestClient(cfg, []byte("secret-token"), roots)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c
	t.Cleanup(func() { c.Close() })
	f.budget = newBudget(f.now.Add(5*time.Second), func() time.Time { return f.now })
	return f
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	user := "@audit:example.org"
	if r.Header.Get("Authorization") == "Bearer reader-token" {
		user = "@reader:example.org"
	} else if r.Header.Get("Authorization") != "Bearer secret-token" {
		f.t.Error("missing bearer")
		w.WriteHeader(401)
		return
	}
	if r.URL.RawQuery != "" && !strings.HasSuffix(r.URL.Path, "/messages") {
		f.t.Error("unexpected query")
	}
	f.paths = append(f.paths, r.URL.EscapedPath())
	switch {
	case strings.HasSuffix(r.URL.Path, "/whoami"):
		f.now = f.now.Add(f.advanceWho)
		json.NewEncoder(w).Encode(f.who)
	case strings.HasSuffix(r.URL.Path, "/state"):
		f.now = f.now.Add(f.advanceState)
		w.WriteHeader(f.stateStatus)
		if f.stateBody != nil {
			w.Write(f.stateBody)
		} else {
			json.NewEncoder(w).Encode(f.state)
		}
	case strings.HasSuffix(r.URL.Path, "/messages"):
		f.filters = append(f.filters, r.URL.Query().Get("filter"))
		if r.URL.Query().Get("dir") != "b" || r.URL.Query().Get("limit") != "1024" {
			f.t.Error("unbounded or forward head read")
		}
		if f.page >= len(f.pages) {
			f.t.Error("unexpected history page")
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(f.pages[f.page])
		f.page++
	case r.Method == "PUT":
		typ := EventType
		if strings.Contains(r.URL.Path, "/redact/") {
			typ = "m.room.redaction"
		} else if _, suffix, ok := strings.Cut(r.URL.Path, "/send/"); ok {
			typ, _, _ = strings.Cut(suffix, "/")
		}
		if status := policyPermission(f.state, user, typ); status != 200 {
			w.WriteHeader(status)
			return
		}
		f.puts++
		f.now = f.now.Add(f.advancePut)
		var c map[string]any
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			f.t.Error(err)
		}
		expectedHash := sha256.Sum256(original)
		if c["line"] != string(original[:len(original)-1]) || c["seq"] != float64(1) || c["sha256"] != fmt.Sprintf("%x", expectedHash) {
			f.t.Error("PUT content differs from original persisted bytes")
		}
		if strings.Contains(r.URL.String(), "secret-token") {
			f.t.Error("token in URL")
		}
		if len(c) != 3 {
			f.t.Error("content schema")
		}
		raw, _ := json.Marshal(c)
		if _, ok := f.events[r.URL.EscapedPath()]; !ok || f.duplicate {
			f.events[fmt.Sprint(r.URL.EscapedPath(), f.puts*fbool(f.duplicate))] = raw
		}
		w.WriteHeader(f.putStatus)
		if f.putBody != nil {
			w.Write(f.putBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"event_id": eventID})
		}
	case r.Method == "GET":
		f.gets++
		f.now = f.now.Add(f.advanceGet)
		w.WriteHeader(f.getStatus)
		if f.getBody != nil {
			w.Write(f.getBody)
			return
		}
		h := sha256.Sum256(original)
		c := map[string]any{"line": string(original[:len(original)-1]), "seq": 1, "sha256": hex.EncodeToString(h[:])}
		e := map[string]any{"event_id": eventID, "room_id": room, "sender": f.c.cfg.User, "type": EventType, "content": c}
		if f.mutate != nil {
			f.mutate(e)
		}
		json.NewEncoder(w).Encode(e)
	default:
		f.t.Error("unexpected method")
	}
}
func fbool(b bool) int {
	if b {
		return 1
	}
	return 0
}
func (f *fixture) attempt() (*Verified, error) {
	d, err := f.c.Delivery(original)
	if err != nil {
		return nil, err
	}
	return d.Attempt(context.Background(), f.budget)
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

// Each rejected response has a nearby exact-byte success control; outer JSON spelling is immaterial.
func TestReadback(t *testing.T) {
	cases := map[string]func(map[string]any){
		"line":   func(e map[string]any) { e["content"].(map[string]any)["line"] = `{"seq":2}` },
		"hash":   func(e map[string]any) { e["content"].(map[string]any)["sha256"] = strings.Repeat("a", 64) },
		"seq":    func(e map[string]any) { e["content"].(map[string]any)["seq"] = 2 },
		"extra":  func(e map[string]any) { e["content"].(map[string]any)["extra"] = true },
		"sender": func(e map[string]any) { e["sender"] = "@other:example.org" }, "room": func(e map[string]any) { e["room_id"] = "!other:example.org" }, "type": func(e map[string]any) { e["type"] = "wrong" }, "event": func(e map[string]any) { e["event_id"] = "$wrong" },
		"state": func(e map[string]any) { e["state_key"] = "" }, "redacted": func(e map[string]any) { e["unsigned"] = map[string]any{"redacted_because": map[string]any{}} }, "redacts": func(e map[string]any) { e["redacts"] = eventID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			f.mutate = mutate
			_, err := f.attempt()
			requireCode(t, err, "audit_unavailable")
			f.mutate = nil
			if _, err = f.attempt(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("escaping-control", func(t *testing.T) {
		f := setup(t)
		h := sha256.Sum256(original)
		f.getBody = []byte(fmt.Sprintf(`{"content":{"sha256":"%x","seq":1,"line":"{\u0022seq\u0022:1}"},"type":%q,"sender":%q,"room_id":%q,"event_id":%q}`, h, EventType, f.c.cfg.User, room, eventID))
		if _, err := f.attempt(); err != nil {
			t.Fatal(err)
		}
	})
}

// No PUT or read-back response at/after the deadline can produce a candidate; the same strict boundary applies to final hooks.
func TestBudget(t *testing.T) {
	for _, step := range []string{"put", "get", "hook"} {
		for _, delta := range []time.Duration{5 * time.Second, 5*time.Second + 1, 5*time.Second - 1} {
			t.Run(fmt.Sprint(step, delta), func(t *testing.T) {
				f := setup(t)
				if step == "put" {
					f.advancePut = delta
				}
				if step == "get" {
					f.advanceGet = delta
				}
				v, err := f.attempt()
				if step == "hook" && err == nil {
					err = v.complete(context.Background(), func(context.Context, Position, *Budget) error { f.now = f.now.Add(delta); return nil })
				}
				if delta >= 5*time.Second {
					requireCode(t, err, "audit_unavailable")
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	f := setup(t)
	f.advancePut = 5*time.Second - 1
	f.advanceGet = 1
	_, err := f.attempt()
	requireCode(t, err, "audit_unavailable")
}

// Status, syntax, UTF-8, duplicates, truncation and streaming size refusals do not leak remote diagnostics; valid responses still pass.
func TestResponseFailures(t *testing.T) {
	for _, step := range []string{"put", "get"} {
		for _, status := range []int{401, 403, 429, 500, 503, 404, 300} {
			t.Run(fmt.Sprint(step, status), func(t *testing.T) {
				f := setup(t)
				if step == "put" {
					f.putStatus = status
				} else {
					f.getStatus = status
				}
				_, err := f.attempt()
				requireCode(t, err, "audit_unavailable")
				f.putStatus = 200
				f.getStatus = 200
				if _, err = f.attempt(); err != nil {
					t.Fatal(err)
				}
			})
		}
		bodies := [][]byte{[]byte(`{`), []byte(`{}`), []byte(`{"event_id":7}`), []byte(`{"event_id":"$bad"}`), []byte(`{"event_id":null}`), []byte(`{"event_id":"$` + strings.Repeat("A", 42) + `B"}`), []byte(`{"event_id":"` + eventID + `=","x":0}`), []byte(`{"event_id":"` + eventID + `","event_id":"` + eventID + `"}`), bytes.Repeat([]byte("x"), 65537), {0xff}}
		for i, b := range bodies {
			t.Run(fmt.Sprint(step, "body", i), func(t *testing.T) {
				f := setup(t)
				if step == "put" {
					f.putBody = b
				} else {
					f.getBody = b
				}
				_, err := f.attempt()
				requireCode(t, err, "audit_unavailable")
				if strings.Contains(err.Error(), "secret-token") {
					t.Fatal("leak")
				}
				f.putBody = nil
				f.getBody = nil
				if _, err = f.attempt(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// A retry holds exact request bytes/path and creates one event; the duplicate plant is detected by this same checker.
func TestRetryAndHarness(t *testing.T) {
	for _, plant := range []bool{false, true} {
		t.Run(fmt.Sprint(plant), func(t *testing.T) {
			f := setup(t)
			f.duplicate = plant
			d, err := f.c.Delivery(original)
			if err != nil {
				t.Fatal(err)
			}
			f.getStatus = 503
			_, err = d.Attempt(context.Background(), f.budget)
			requireCode(t, err, "audit_unavailable")
			f.getStatus = 200
			if _, err = d.Attempt(context.Background(), f.budget); err != nil {
				t.Fatal(err)
			}
			caught := len(f.events) != 1
			if caught != plant {
				t.Fatalf("duplicate assertion: count=%d plant=%t", len(f.events), plant)
			}
			if f.puts != 2 {
				t.Fatal("retry missing")
			}
		})
	}
	// The planted byte mismatch must reach the exact comparison with all metadata valid.
	f := setup(t)
	f.mutate = func(e map[string]any) { e["content"].(map[string]any)["line"] = `{"seq":2}` }
	_, err := f.attempt()
	requireCode(t, err, "audit_unavailable")
}

// Reserved/non-ASCII room bytes remain one component, with no query/fragment injection; event and txn components are pinned too.
func TestPathsAndProxy(t *testing.T) {
	proxyHits := 0
	p := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyHits++ }))
	defer p.Close()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, p.URL)
	}
	f := setup(t)
	if _, err := f.attempt(); err != nil {
		t.Fatal(err)
	}
	if proxyHits != 0 {
		t.Fatal("proxy used")
	}
	h := sha256.Sum256(original)
	want := "/_matrix/client/v3/rooms/%21a%2Fb%3Fc%23%20%C3%A9:example.org" + "/send/" + component(EventType) + "/" + component(fmt.Sprintf("audit-v0-%x", h))
	if f.paths[2] != want || f.paths[3] != "/_matrix/client/v3/rooms/"+component(room)+"/event/"+component(eventID) {
		t.Fatalf("paths %q", f.paths)
	}
}

// Redirects never reach either target, even on the authenticated origin.
func TestRedirects(t *testing.T) {
	for _, cross := range []bool{false, true} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(fmt.Sprint(cross, status), func(t *testing.T) {
				f := setup(t)
				hits := 0
				target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits++
					if r.Header.Get("Authorization") != "" {
						t.Error("token reached target")
					}
				}))
				defer target.Close()
				destination := f.server.URL + "/redirect-target"
				if cross {
					destination = target.URL
				}
				f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/redirect-target" {
						hits++
						return
					}
					http.Redirect(w, r, destination, status)
				})
				_, err := f.attempt()
				requireCode(t, err, "audit_unavailable")
				if hits != 0 {
					t.Fatal("redirect followed")
				}
			})
		}
	}
}

// Startup never rebinds identity/device or recreates a lost binding for retained lines; matching custody survives restart.
func TestBinding(t *testing.T) {
	for _, field := range []string{"origin", "room", "user", "device", "missing", "mode", "symlink"} {
		t.Run(field, func(t *testing.T) {
			f := setup(t)
			cfg := f.c.cfg
			f.c.Close()
			raw, err := os.ReadFile(cfg.BindingPath)
			if err != nil {
				t.Fatal(err)
			}
			var b map[string]any
			json.Unmarshal(raw, &b)
			switch field {
			case "origin", "room", "user", "device":
				b[field] = "changed"
				raw, _ = json.Marshal(b)
				os.WriteFile(cfg.BindingPath, raw, 0600)
			case "missing":
				os.Remove(cfg.BindingPath)
			case "mode":
				os.Chmod(cfg.BindingPath, 0644)
			case "symlink":
				os.Rename(cfg.BindingPath, cfg.BindingPath+"old")
				os.Symlink(cfg.BindingPath+"old", cfg.BindingPath)
			}
			roots := x509.NewCertPool()
			roots.AddCert(f.server.Certificate())
			c, err := newTestClient(cfg, []byte("secret-token"), roots)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.startup(context.Background(), f.budget, true, nil)
			requireCode(t, err, "audit_room_unavailable")
		})
	}
	f := setup(t)
	f.c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	c, err := newTestClient(f.c.cfg, []byte("secret-token"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.startup(context.Background(), f.budget, true, nil); err != nil {
		t.Fatal(err)
	}
}

// Revocation uses static phase-specific codes; filesystem/network/JSON details and token material remain absent.
func TestSecrecyAndUnknownToken(t *testing.T) {
	f := setup(t)
	f.putStatus = 401
	f.putBody = []byte(`{"errcode":"M_UNKNOWN_TOKEN","error":"secret-response"}`)
	_, err := f.attempt()
	requireCode(t, err, "audit_unavailable")
	f.c.Close()
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401); w.Write(f.putBody) })
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	c, err := newTestClient(f.c.cfg, []byte("secret-token"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.startup(context.Background(), f.budget, true, nil)
	requireCode(t, err, "audit_room_unavailable")
	for _, secret := range []string{"secret-token", f.c.cfg.BindingPath, "secret-response", "Authorization"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("secret leak")
		}
	}
}

// Only test builds can inject roots; production has no CA configuration option.
func newTestClient(cfg Config, token []byte, roots *x509.CertPool) (*Client, error) {
	c, err := newClient(cfg, token)
	if err != nil {
		return nil, err
	}
	c.http.Transport.(*transport).tls.RootCAs = roots
	return c, nil
}

// Every supplied invalid binding/proof fails before a send; exact private binding remains usable.
func TestStartupProofAndWhoami(t *testing.T) {
	for _, body := range []string{`{"user_id":"@audit:example.org"}`, `{"user_id":"@audit:example.org","device_id":""}`, `{"user_id":"@audit:example.org","device_id":1}`, `{"user_id":"@other:example.org","device_id":"DEVICE"}`} {
		t.Run(body, func(t *testing.T) {
			f := setup(t)
			f.c.Close()
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			roots := x509.NewCertPool()
			roots.AddCert(f.server.Certificate())
			c, err := newTestClient(f.c.cfg, []byte("secret-token"), roots)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.startup(context.Background(), f.budget, true, nil)
			code := "audit_room_unavailable"
			if strings.Contains(body, "@other") {
				code = "audit_room_policy_invalid"
			}
			requireCode(t, err, code)
			if f.puts != 0 {
				t.Fatal("startup sent event")
			}
		})
	}
	for _, proof := range []bool{false, true} {
		t.Run(fmt.Sprint("proof", proof), func(t *testing.T) {
			f := setup(t)
			f.c.Close()
			os.Remove(f.c.cfg.BindingPath)
			roots := x509.NewCertPool()
			roots.AddCert(f.server.Certificate())
			c, err := newTestClient(f.c.cfg, []byte("secret-token"), roots)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var hook func(context.Context, *Budget) error
			if proof {
				hook = func(context.Context, *Budget) error { return nil }
			}
			err = c.startup(context.Background(), f.budget, false, hook)
			if !proof {
				requireCode(t, err, "audit_room_unavailable")
				if _, err = os.Stat(c.cfg.BindingPath); !os.IsNotExist(err) {
					t.Fatal("binding written without proof")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// No TLS bypass/system-CA override is exposed; plaintext origins and invalid tokens fail before HTTP, and TLS errors are static.
func TestTransportAndLocalFailures(t *testing.T) {
	f := setup(t)
	for _, origin := range []string{"http://example.org", "https://example.org/", "https://example.org?", "https://example.org#", "https://user@example.org"} {
		cfg := f.c.cfg
		cfg.Origin = origin
		_, err := newClient(cfg, []byte("secret-token"))
		requireCode(t, err, "configuration_invalid")
	}
	for _, token := range [][]byte{nil, []byte("token\n"), bytes.Repeat([]byte("x"), 4097)} {
		_, err := newClient(f.c.cfg, token)
		requireCode(t, err, "configuration_invalid")
	}
	c, err := newClient(f.c.cfg, []byte("secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.request(context.Background(), f.budget, "GET", []string{"account", "whoami"}, nil)
	requireCode(t, err, "audit_unavailable")
	f.c.Close()
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	cfg := f.c.cfg
	cfg.BindingPath = filepath.Join(cfg.BindingPath, "token-path-secret")
	c2, err := newTestClient(cfg, []byte("secret-token"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	err = c2.startup(context.Background(), f.budget, true, nil)
	requireCode(t, err, "audit_room_unavailable")
	for _, s := range []string{cfg.BindingPath, "secret-token", "Authorization", "token-path-secret"} {
		if strings.Contains(err.Error(), s) {
			t.Fatal("local diagnostic leaked")
		}
	}
}

// Retrying cannot reset the budget or regenerate payload after caller-buffer changes; final work is mandatory and errors stay static.
func TestFinalizationAndSnapshot(t *testing.T) {
	f := setup(t)
	raw := bytes.Clone(original)
	d, err := f.c.Delivery(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X'
	v, err := d.Attempt(context.Background(), f.budget)
	if err != nil {
		t.Fatal(err)
	}
	requireCode(t, v.complete(context.Background(), nil), "audit_unavailable")
	requireCode(t, v.complete(context.Background(), func(context.Context, Position, *Budget) error { return fmt.Errorf("secret-response") }), "audit_unavailable")
	if err = v.complete(context.Background(), func(_ context.Context, p Position, b *Budget) error {
		if p.EventID != eventID || p.RoomID != room || p.Sequence != 1 || b != f.budget {
			t.Fatal("wrong candidate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	requireCode(t, v.complete(context.Background(), func(context.Context, Position, *Budget) error { return nil }), "audit_unavailable")
	_, err = d.Attempt(context.Background(), newBudget(f.now.Add(5*time.Second), func() time.Time { return f.now }))
	requireCode(t, err, "audit_unavailable")
	bad := newBudget(f.now.Add(6*time.Second), func() time.Time { return f.now })
	f.now = f.now.Add(time.Second)
	if bad.check(context.Background()) == nil {
		t.Fatal("overlong original budget accepted")
	}
}

// A changed authenticated device never rebinds an intact retained file or sends, while the original device remains valid.
func TestAuthenticatedDeviceContinuity(t *testing.T) {
	f := setup(t)
	f.c.Close()
	saved, err := os.ReadFile(f.c.cfg.BindingPath)
	if err != nil {
		t.Fatal(err)
	}
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/whoami") {
			fmt.Fprint(w, `{"user_id":"@audit:example.org","device_id":"CHANGED"}`)
		} else {
			f.serve(w, r)
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	c, err := newTestClient(f.c.cfg, []byte("secret-token"), roots)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	requireCode(t, c.startup(context.Background(), f.budget, true, nil), "audit_room_unavailable")
	after, err := os.ReadFile(f.c.cfg.BindingPath)
	if err != nil || !bytes.Equal(saved, after) || f.puts != 0 {
		t.Fatal("device change modified custody")
	}
	f.server.Config.Handler = http.HandlerFunc(f.serve)
	if err = c.startup(context.Background(), f.budget, true, nil); err != nil {
		t.Fatal(err)
	}
}

// The streaming cap rejects otherwise-valid JSON at 64 KiB + 1; the exact-limit control succeeds for each endpoint.
func TestStreamingLimit(t *testing.T) {
	for _, step := range []string{"put", "get"} {
		for _, size := range []int{65537, 65536} {
			t.Run(fmt.Sprint(step, size), func(t *testing.T) {
				f := setup(t)
				h := sha256.Sum256(original)
				var body []byte
				if step == "put" {
					body, _ = json.Marshal(map[string]any{"event_id": eventID})
				} else {
					body, _ = json.Marshal(map[string]any{"event_id": eventID, "room_id": room, "sender": f.c.cfg.User, "type": EventType, "content": map[string]any{"line": string(original[:len(original)-1]), "seq": 1, "sha256": fmt.Sprintf("%x", h)}})
				}
				body = append(body, bytes.Repeat([]byte(" "), size-len(body))...)
				if step == "put" {
					f.putBody = body
				} else {
					f.getBody = body
				}
				_, err := f.attempt()
				if size > 65536 {
					requireCode(t, err, "audit_unavailable")
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Invalid persisted framing/sequence cannot send; canonical original bytes are the positive control.
func TestOriginalLineContract(t *testing.T) {
	f := setup(t)
	for _, raw := range [][]byte{nil, []byte(`{"seq":1}`), []byte("{\"seq\":0}\n"), []byte("{\"seq\":\"1\"}\n"), []byte("{ \"seq\":1}\n"), []byte("{\"seq\":1}\n\n")} {
		_, err := f.c.Delivery(raw)
		requireCode(t, err, "audit_unavailable")
	}
	if f.puts != 0 {
		t.Fatal("invalid original sent")
	}
	if _, err := f.attempt(); err != nil {
		t.Fatal(err)
	}
}

// An authenticated peer sending malformed HTTP framing cannot put response
// material into the process logger; the error remains static.
func TestUnsolicitedResponseSecrecy(t *testing.T) {
	f := setup(t)
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(old)
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		buf.WriteString("secret-response\r\n")
		buf.Flush()
	})
	_, err := f.attempt()
	requireCode(t, err, "audit_unavailable")
	if strings.Contains(output.String(), "secret-response") || strings.Contains(output.String(), "secret-token") {
		t.Fatal("transport logger leaked peer bytes")
	}
}
