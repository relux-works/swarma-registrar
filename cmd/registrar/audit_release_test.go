package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/internal/adapters"
	"github.com/relux-works/swarma-registrar/internal/admission"
	"github.com/relux-works/swarma-registrar/internal/audittest"
)

func matrixCommand(t *testing.T, f *fixtureData, hs *audittest.Server, clocks ...admission.Clock) (string, *http.Client) {
	t.Helper()
	d := testDependencies(t, f, false, false)
	d.open = func(ctx context.Context, c adapters.Config, _ time.Time, confirm bool, terminal terminalOpener, out io.Writer) (*runtime, error) {
		a, err := adapters.NewAudit(ctx, c.AuditFile, nil, c.ObjectFormat)
		if err != nil {
			return nil, err
		}
		if err = a.ConnectMatrix(hs.Context(ctx), hs.Config(filepath.Join(filepath.Dir(c.AuditFile), "binding")), []byte(audittest.Token)); err != nil {
			a.Close()
			return nil, err
		}
		snapshot, err := startRegistry(ctx, c, f.source, f.store, confirm, terminal, out)
		if err != nil {
			a.Close()
			return nil, err
		}
		h := a.Head()
		var clock admission.Clock = testClock{}
		if len(clocks) > 0 {
			clock = clocks[0]
		}
		handler, err := wire(c, snapshot, clock, healthyStartup(), f.signer, auditBridge{a}, admission.AuditHead{Sequence: h.Sequence, Hash: h.Hash})
		if err != nil {
			a.Close()
			return nil, err
		}
		return &runtime{handler: handler, drain: handler.Drain, close: a.Close}, nil
	}
	return startTestServer(t, d, true, true)
}
func registrationResult(t *testing.T, url string, client *http.Client, raw []byte) (int, string, string) {
	t.Helper()
	response, err := client.Post(url+"/v1/registration", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct{ JWT, Code string }
	if json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatal("invalid command response")
	}
	return response.StatusCode, result.JWT, result.Code
}
func outcomes(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := []map[string]any{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var event map[string]any
		if json.Unmarshal(line, &event) != nil {
			t.Fatal("invalid retained line")
		}
		result = append(result, event)
	}
	return result
}

// Real command HTTP requests use the reconciled TLS adapter. Each ACK failure
// releases zero JWTs, preserves the consumed nonce and retains its refusal;
// the adjacent control releases exactly one signed JWT over two identical proofs.
func TestMatrixCommandRelease(t *testing.T) {
	for _, mode := range []string{"put", "readback", "bytes", "scan", "write", "anchor", "policy", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := fixture(t)
			hs := audittest.New(t)
			url, client := matrixCommand(t, f, hs)
			hook := func() {}
			if mode == "write" {
				hook = func() {
					if err := os.Chmod(filepath.Join(filepath.Dir(f.config.AuditFile), "binding.coverage"), 0644); err != nil {
						t.Error(err)
					}
				}
			}
			hs.Set(mode, hook)
			status, jwt, code := registrationResult(t, url, client, proof(t))
			released := 0
			if jwt != "" {
				released++
				parts := strings.Split(jwt, ".")
				if len(parts) != 3 {
					t.Fatal("invalid JWT")
				}
				sig, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil || !ed25519.Verify(private(9).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
					t.Fatal("invalid JWT signature")
				}
			}
			if mode == "valid" {
				if status != 200 || jwt == "" {
					t.Fatalf("acknowledged issuance did not release: %d/%s", status, code)
				}
			} else if status != 503 || code != "audit_unavailable" || jwt != "" {
				t.Fatalf("completion failure released JWT or changed refusal: %d/%s jwt=%t", status, code, jwt != "")
			}
			if mode == "scan" || mode == "write" {
				_, puts, reads := hs.Counts()
				if puts != 1 || reads != 1 {
					t.Fatal("coverage failure did not follow successful Attempt")
				}
			}
			records := outcomes(t, f.config.AuditFile)
			if mode != "valid" {
				refused := false
				for _, record := range records {
					if record["outcome"] == "refused" && record["code"] == "audit_unavailable" {
						refused = true
					}
				}
				if !refused {
					t.Fatal("acknowledgement failure lost refused line")
				}
				if mode == "policy" && len(records) != 1 {
					t.Fatal("failed precheck appended candidate")
				}
			}
			status, jwt, code = registrationResult(t, url, client, proof(t))
			if jwt != "" {
				released++
			}
			if status != 409 || code != "nonce_replayed" || jwt != "" {
				t.Fatalf("consumed nonce was restored: %d/%s jwt=%t", status, code, jwt != "")
			}
			want := 0
			if mode == "valid" {
				want = 1
			}
			if released != want {
				t.Fatalf("released %d JWTs, want exactly %d", released, want)
			}
			if mode == "valid" {
				events, puts, reads := hs.Counts()
				if events != 2 || puts != 2 || reads != 2 {
					t.Fatalf("missing issued/refused exact acknowledgements: %d/%d/%d", events, puts, reads)
				}
			}
		})
	}
}

// A remote conflict introduced after a successful issuance must be detected on
// the next request before its candidate append; it still consumes that new nonce.
func TestMatrixCommandEveryIssuancePrecheck(t *testing.T) {
	for _, mode := range []string{"head", "anchor"} {
		t.Run(mode, func(t *testing.T) {
			f := fixture(t)
			hs := audittest.New(t)
			url, client := matrixCommand(t, f, hs)
			status, jwt, _ := registrationResult(t, url, client, proof(t))
			if status != 200 || jwt == "" {
				t.Fatal("positive issuance control")
			}
			hs.Set(mode, nil)
			// The next proof differs only in its nonce, with a valid fresh signature.
			var parsed map[string]any
			if json.Unmarshal(proof(t), &parsed) != nil {
				t.Fatal("fixture")
			}
			body := parsed["body"].(map[string]any)
			body["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 16))
			next, _ := signed(t, envelope.Registration, body, 2)
			status, jwt, code := registrationResult(t, url, client, next)
			if status != 503 || jwt != "" || code != "audit_unavailable" {
				t.Fatal("per-issuance coverage check bypassed")
			}
			records := outcomes(t, f.config.AuditFile)
			if len(records) != 2 || records[1]["outcome"] != "refused" {
				t.Fatal("failed per-issuance precheck appended candidate")
			}
			status, jwt, code = registrationResult(t, url, client, next)
			if status != 409 || jwt != "" || code != "nonce_replayed" {
				t.Fatal("precheck failure restored nonce")
			}
		})
	}
}

// A batch of early refusals keeps each HTTP verdict while every original line
// receives read-back and durable Complete coverage, with no JWT or skipped line.
func TestMatrixCommandRefusalBatch(t *testing.T) {
	f := fixture(t)
	hs := audittest.New(t)
	url, client := matrixCommand(t, f, hs)
	for i := 0; i < 32; i++ {
		status, jwt, code := registrationResult(t, url, client, []byte(`{}`))
		if status != 400 || jwt != "" || code != "registration_malformed" {
			t.Fatalf("refusal changed: %d/%s", status, code)
		}
	}
	records := outcomes(t, f.config.AuditFile)
	lines := hs.Lines()
	if len(records) != 32 || len(lines) != 32 {
		t.Fatal("batch lost refusal/coverage")
	}
	for i, record := range records {
		if record["seq"] != float64(i+1) || record["outcome"] != "refused" {
			t.Fatal("batch order changed")
		}
	}
	events, puts, reads := hs.Counts()
	if events != 32 || puts != 32 || reads != 32 {
		t.Fatal("batch was not acknowledged exactly once per line")
	}
}

// The actual worker wakes after a failed read-back, reconstructs the accepted
// prefix and replays only the refusal. Recovery never releases the old JWT or nonce.
func TestMatrixCommandAutomaticRecovery(t *testing.T) {
	f := fixture(t)
	hs := audittest.New(t)
	url, client := matrixCommand(t, f, hs)
	hs.Set("readback", nil)
	status, jwt, code := registrationResult(t, url, client, proof(t))
	if status != 503 || jwt != "" || code != "audit_unavailable" {
		t.Fatal("uncertain issuance escaped")
	}
	response, err := client.Get(url + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("delivery failure left readiness open")
	}
	hs.Set("valid", nil)
	deadline := time.Now().Add(4 * time.Second)
	for {
		response, err = client.Get(url + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("automatic recovery did not reopen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	events, puts, reads := hs.Counts()
	if events != 2 || puts != 2 || reads != 2 {
		t.Fatalf("worker re-PUT verified prefix: %d/%d/%d", events, puts, reads)
	}
	status, jwt, code = registrationResult(t, url, client, proof(t))
	if status != 409 || jwt != "" || code != "nonce_replayed" {
		t.Fatal("recovery restored old nonce/JWT")
	}
}

type shortAuditClock struct{ testClock }

func (shortAuditClock) Deadline(ctx context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 2*time.Second)
}

// A blocked off-host read cannot hold admission/local state: a concurrent
// replayed nonce is refused and spooled before its own bounded ACK wait expires.
// Neither the owner nor waiter releases a JWT, and expired issuance keeps refusal.
func TestMatrixCommandSlowDelivery(t *testing.T) {
	f := fixture(t)
	hs := audittest.New(t)
	url, client := matrixCommand(t, f, hs, shortAuditClock{})
	entered := make(chan struct{})
	release := make(chan struct{})
	hs.Set("valid", func() { close(entered); <-release })
	defer close(release)
	type result struct {
		status    int
		jwt, code string
	}
	first := make(chan result, 1)
	go func() {
		status, jwt, code := registrationResult(t, url, client, proof(t))
		first <- result{status, jwt, code}
	}()
	select {
	case <-entered:
	case <-time.After(4 * time.Second):
		t.Fatal("slow test did not reach read-back")
	}
	status, jwt, code := registrationResult(t, url, client, proof(t))
	if status != 409 || jwt != "" || code != "nonce_replayed" {
		t.Fatal("slow ACK blocked ordered admission or changed refusal")
	}
	got := <-first
	if got.status != 503 || got.jwt != "" || got.code != "audit_unavailable" {
		t.Fatal("expired delivery released JWT")
	}
	deadline := time.Now().Add(time.Second)
	for {
		records := outcomes(t, f.config.AuditFile)
		found := false
		for _, r := range records {
			if r["code"] == "audit_unavailable" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired delivery lost refusal spool")
		}
		time.Sleep(time.Millisecond)
	}
}
