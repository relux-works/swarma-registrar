package matrixaudit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
)

type reconciliationFixture struct {
	f        *fixture
	r        *Reconciliation
	events   []map[string]any
	requests []string
	override func(http.ResponseWriter, *http.Request) bool
	pageSize int
	advance  time.Duration
}

func auditLine(seq int, prev string) []byte {
	raw, _ := ccj.Marshal(map[string]any{"seq": int64(seq), "prev_hash": prev}, "audit_unavailable")
	return append(raw, '\n')
}
func auditEvent(seq int, line []byte) map[string]any {
	raw := make([]byte, 32)
	raw[0] = byte(seq)
	raw[1] = byte(seq >> 8)
	return map[string]any{"event_id": "$" + base64.RawURLEncoding.EncodeToString(raw), "room_id": room, "type": EventType, "sender": "@audit:example.org", "content": map[string]any{"seq": int64(seq), "line": string(line[:len(line)-1]), "sha256": digest(line)}}
}
func chain(n int) ([][]byte, []map[string]any) {
	lines := [][]byte{}
	events := []map[string]any{}
	prev := strings.Repeat("0", 64)
	for i := 1; i <= n; i++ {
		line := auditLine(i, prev)
		lines = append(lines, line)
		events = append(events, auditEvent(i, line))
		prev = digest(line)
	}
	return lines, events
}
func newReconciliationFixture(t *testing.T) *reconciliationFixture {
	t.Helper()
	f := setupServer(t)
	x := &reconciliationFixture{f: f, pageSize: 1024}
	fallback := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "PUT" {
			var content map[string]any
			if json.NewDecoder(req.Body).Decode(&content) != nil {
				t.Error("bad delivery body")
			}
			line, _ := content["line"].(string)
			hash := digest(append([]byte(line), '\n'))
			if content["sha256"] != hash || !strings.HasSuffix(req.URL.Path, "audit-v0-"+hash) {
				t.Error("delivery changed original bytes or transaction ID")
			}
			seq := int(content["seq"].(float64))
			event := auditEvent(seq, append([]byte(line), '\n'))
			x.events = append(x.events, event)
			f.puts++
			json.NewEncoder(w).Encode(map[string]any{"event_id": event["event_id"]})
			return
		}
		if strings.Contains(req.URL.Path, "/event/") {
			id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			for _, event := range x.events {
				if event["event_id"] == id {
					f.gets++
					json.NewEncoder(w).Encode(event)
					return
				}
			}
			w.WriteHeader(404)
			return
		}
		if !strings.Contains(req.URL.Path, "/context/") && !strings.HasSuffix(req.URL.Path, "/messages") {
			fallback.ServeHTTP(w, req)
			return
		}
		x.requests = append(x.requests, req.URL.EscapedPath()+"?"+req.URL.RawQuery)
		f.now = f.now.Add(x.advance)
		if x.override != nil && x.override(w, req) {
			return
		}
		filter := req.URL.Query().Get("filter")
		if filter != auditFilter && filter != coverageFilters[0] && filter != coverageFilters[1] {
			t.Error("wrong filter")
		}
		if strings.Contains(req.URL.Path, "/context/") {
			id := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			idx := -1
			for i, e := range x.events {
				if e["event_id"] == id {
					idx = i
					break
				}
			}
			if idx < 0 {
				w.WriteHeader(404)
				return
			}
			before := []any{}
			after := []any{}
			if req.URL.Query().Get("limit") == "1024" {
				for i := idx - 1; i >= 0; i-- {
					if filterOK(x.events[i], filter) {
						before = append(before, x.events[i])
						break
					}
				}
			}
			start := idx
			if len(before) > 0 {
				start = idx - 1
			}
			json.NewEncoder(w).Encode(map[string]any{"event": x.events[idx], "events_before": before, "events_after": after, "start": fmt.Sprint("p", start), "end": fmt.Sprint("p", idx+1), "state": []any{}})
			return
		}
		from := req.URL.Query().Get("from")
		forward := req.URL.Query().Get("dir") == "f"
		pos := len(x.events)
		if from != "" {
			var err error
			pos, err = strconv.Atoi(strings.TrimPrefix(from, "p"))
			if err != nil || pos < 0 || pos > len(x.events) {
				w.WriteHeader(400)
				return
			}
		} else {
			from = fmt.Sprint("p", pos)
		}
		endBound := len(x.events)
		if upper := req.URL.Query().Get("to"); upper != "" {
			endBound, _ = strconv.Atoi(strings.TrimPrefix(upper, "p"))
		}
		chunk := []any{}
		cursor := pos
		for len(chunk) < x.pageSize && ((forward && cursor < endBound) || (!forward && cursor > 0)) {
			idx := cursor
			if !forward {
				idx--
				cursor--
			} else {
				cursor++
			}
			if filterOK(x.events[idx], filter) {
				chunk = append(chunk, x.events[idx])
			}
		}
		page := map[string]any{"start": from, "chunk": chunk}
		if (forward && cursor < endBound) || (!forward && cursor > 0) {
			page["end"] = fmt.Sprint("p", cursor)
		}
		json.NewEncoder(w).Encode(page)
	})
	if err := startFixture(f); err != nil {
		t.Fatal(err)
	}
	r, err := f.c.OpenReconciliation(context.Background(), f.budget, nil)
	if err != nil {
		t.Fatal(err)
	}
	x.r = r
	t.Cleanup(func() { r.Close() })
	return x
}
func (x *reconciliationFixture) recover(lines [][]byte) error {
	return x.r.Recover(context.Background(), x.f.budget, lines)
}
func (x *reconciliationFixture) restart(t *testing.T) {
	t.Helper()
	x.r.Close()
	x.f.c.Close()
	x.f.now = time.Now()
	x.f.budget = newBudget(x.f.now.Add(5*time.Second), func() time.Time { return x.f.now })
	if err := startFixture(x.f); err != nil {
		t.Fatal(err)
	}
	r, err := x.f.c.OpenReconciliation(context.Background(), x.f.budget, [][]byte{auditLine(1, strings.Repeat("0", 64))})
	if err != nil {
		t.Fatal(err)
	}
	x.r = r
	t.Cleanup(func() { r.Close() })
}
func membershipEvent(n int, user, sender, before, after string) map[string]any {
	raw := make([]byte, 32)
	raw[0] = 200
	raw[1] = byte(n)
	return map[string]any{"event_id": "$" + base64.RawURLEncoding.EncodeToString(raw), "room_id": room, "type": "m.room.member", "sender": sender, "state_key": user, "content": map[string]any{"membership": after}, "unsigned": map[string]any{"prev_content": map[string]any{"membership": before}}}
}

// A valid head over an older malformed event fails full prefix verification;
// a complete one-event prefix recovers its receipt with zero PUTs.
func TestPrefixRejectsOlderMalformedEvent(t *testing.T) {
	for _, bad := range []bool{true, false} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if bad {
				x.events = append([]map[string]any{{"type": EventType}}, events...)
				p := Position{events[0]["event_id"].(string), room, 1, digest(lines[0])}
				if err := x.f.c.ReconcileHead(context.Background(), x.f.budget, &p, lines[0]); err != nil {
					t.Fatal("head trap fixture invalid", err)
				}
			}
			err := x.recover(lines)
			if bad {
				requireCode(t, err, "audit_room_head_mismatch")
			} else if err != nil {
				t.Fatal(err)
			}
			if x.f.puts != 0 {
				t.Fatal("prefix verification sent an event")
			}
		})
	}
}

// Recovery reconstructs an exact remote prefix durably despite missing receipts,
// preserves a queued suffix across restart without relying on transaction dedup.
func TestDurableLostReceiptPrefix(t *testing.T) {
	x := newReconciliationFixture(t)
	lines, events := chain(3)
	x.events = events[:2]
	x.pageSize = 1
	if err := x.recover(lines); err != nil {
		t.Fatal(err)
	}
	p, line := x.r.Receipt()
	if p.Sequence != 2 || p.EventID != events[1]["event_id"] || !bytes.Equal(line, lines[1]) {
		t.Fatal("lost receipt not reconstructed")
	}
	x.restart(t)
	if err := x.recover(lines); err != nil {
		t.Fatal(err)
	}
	p, line = x.r.Receipt()
	if p.Sequence != 2 || !bytes.Equal(line, lines[1]) || x.f.puts != 0 {
		t.Fatal("recovery replayed prefix or lost original bytes")
	}
	// A returned receipt cannot mutate durable custody.
	line[0] = 'x'
	_, again := x.r.Receipt()
	if !bytes.Equal(again, lines[1]) {
		t.Fatal("receipt aliases state")
	}
}

// Non-prefix histories, including duplicates, gaps, wrong identities, redaction,
// local-chain discontinuity and altered saved IDs, never complete recovery.
func TestPrefixConflicts(t *testing.T) {
	for _, kind := range []string{"remote-ahead", "gap", "duplicate", "sender", "redacted", "line", "local-link", "saved-id"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(3)
			x.events = events
			switch kind {
			case "remote-ahead":
				lines = lines[:2]
			case "gap":
				x.events = append(events[:1], events[2])
			case "duplicate":
				x.events = append(events, events[2])
			case "sender":
				events[0]["sender"] = "@reader:example.org"
			case "redacted":
				events[0]["unsigned"] = map[string]any{"redacted_because": map[string]any{}}
			case "line":
				events[0]["content"].(map[string]any)["line"] = `{"seq":1}`
			case "local-link":
				lines[1] = auditLine(2, strings.Repeat("0", 64))
			case "saved-id":
				if err := x.recover(lines); err != nil {
					t.Fatal(err)
				}
				events[1]["event_id"] = events[0]["event_id"]
			}
			requireCode(t, x.recover(lines), "audit_room_head_mismatch")
			if x.f.c.ready || x.f.puts != 0 {
				t.Fatal("conflicting prefix allowed delivery")
			}
		})
	}
}

// Recovery interval scans allow reader transitions and audit self profile
// updates; forbidden transitions fence durably despite a later benign update.
func TestMembershipCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, user, sender, before, after string
		valid                             bool
	}{
		{"reader-profile", "@reader:example.org", "@reader:example.org", "join", "join", true},
		{"reader-join", "@reader:example.org", "@reader:example.org", "invite", "join", true},
		{"reader-leave", "@reader:example.org", "@reader:example.org", "join", "leave", true},
		{"invite-reject", "@reader:example.org", "@reader:example.org", "invite", "leave", true},
		{"audit-profile", "@audit:example.org", "@audit:example.org", "join", "join", true},
		{"kick", "@reader:example.org", "@audit:example.org", "join", "leave", false},
		{"invite", "@reader:example.org", "@audit:example.org", "leave", "invite", false},
		{"ban", "@reader:example.org", "@reader:example.org", "join", "ban", false},
		{"audit-leave", "@audit:example.org", "@audit:example.org", "join", "leave", false},
		{"audit-join", "@audit:example.org", "@audit:example.org", "invite", "join", false},
		{"audit-target", "@audit:example.org", "@reader:example.org", "join", "join", false},
		{"audit-sender", "@reader:example.org", "@audit:example.org", "join", "join", false},
		{"foreign", "@reader:elsewhere.org", "@reader:elsewhere.org", "join", "join", false},
		{"missing-prior", "@reader:example.org", "@reader:example.org", "", "join", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if err := x.recover(lines); err != nil {
				t.Fatal(err)
			}
			member := membershipEvent(1, tc.user, tc.sender, tc.before, tc.after)
			x.events = append(x.events, member)
			// A later benign current state/profile cannot hide an earlier kick.
			if !tc.valid {
				x.events = append(x.events, membershipEvent(2, "@reader:example.org", "@reader:example.org", "join", "join"))
			}
			err := x.recover(lines)
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				if x.r.state.Marks[1].Event["event_id"] != member["event_id"] {
					t.Fatal("membership watermark did not advance")
				}
			} else {
				requireCode(t, err, "audit_room_policy_invalid")
				if x.r.state.Offender != member["event_id"] {
					t.Fatal("missing incident evidence")
				}
				x.events = events
				x.restart(t)
				requireCode(t, x.recover(lines), "audit_room_policy_invalid")
			}
		})
	}
}

// Timeline and post-first-event state violations survive policy restoration,
// matching audit heads and restart; pre-first-event state failure may recover.
func TestPersistentPolicyFences(t *testing.T) {
	for _, kind := range []string{"timeline", "current", "before-first"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			if kind != "before-first" {
				x.events = events
				if err := x.recover(lines); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "timeline" {
				e := membershipEvent(1, "@reader:example.org", "@reader:example.org", "join", "join")
				e["type"] = "m.room.message"
				x.events = append(x.events, e)
			} else {
				content(x.f, 4)["redact"] = 100
			}
			input := lines
			if kind == "before-first" {
				input = nil
			}
			requireCode(t, x.recover(input), "audit_room_policy_invalid")
			x.f.state = validState()
			x.events = events
			if kind == "before-first" {
				if err := x.recover(lines); err != nil {
					t.Fatal(err)
				}
			} else {
				x.restart(t)
				requireCode(t, x.recover(lines), "audit_room_policy_invalid")
			}
		})
	}
}

// Missing, corrupt, partially written or binding-mismatched coverage cannot be
// initialized from retained history. The unmodified journal reopens successfully.
func TestCoverageJournalCustody(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "missing-empty", "partial", "checksum", "mode", "binding", "symlink", "locked"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if err := x.recover(lines); err != nil {
				t.Fatal(err)
			}
			path := x.r.file.Name()
			x.r.Close()
			switch kind {
			case "missing":
				os.Remove(path)
			case "missing-empty":
				os.Remove(path)
				x.f.c.Close()
				if err := startFixture(x.f); err != nil {
					t.Fatal(err)
				}
				lines = nil
				x.events = nil
			case "partial":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				f.WriteString(`{"partial":`)
				f.Close()
			case "checksum":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.Replace(raw, []byte(`"Sequence":1`), []byte(`"Sequence":2`), 1)
				os.WriteFile(path, raw, 0600)
			case "mode":
				os.Chmod(path, 0644)
			case "binding":
				x.r.c.cfg.Room = "!another:example.org" // Existing binding is checked independently at Start; digest substitution below probes journal binding.
				raw, _ := os.ReadFile(path)
				raw = bytes.Replace(raw, []byte(x.r.binding), []byte(strings.Repeat("0", 64)), 1)
				os.WriteFile(path, raw, 0600)
			case "symlink":
				os.Rename(path, path+".old")
				os.Symlink(path+".old", path)
			}
			x.f.c.ready = true
			r, err := x.f.c.OpenReconciliation(context.Background(), x.f.budget, lines)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				r.Close()
			} else if kind == "locked" {
				if err != nil {
					t.Fatal(err)
				}
				x.f.c.ready = true
				_, err = x.f.c.OpenReconciliation(context.Background(), x.f.budget, lines)
				requireCode(t, err, "audit_room_unavailable")
				r.Close()
			} else {
				requireCode(t, err, "audit_room_unavailable")
			}
		})
	}
}

// Unavailable anchors, discontinuous/cycling tokens, ignored filters, oversized
// arrays and scans at the deadline close readiness without advancing coverage.
func TestCoverageEvidenceFailures(t *testing.T) {
	for _, kind := range []string{"anchor", "boundary", "continuity", "cycle", "filter", "count", "deadline", "write"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if err := x.recover(lines); err != nil {
				t.Fatal(err)
			}
			size := x.r.size
			old := x.r.digest
			x.override = func(w http.ResponseWriter, req *http.Request) bool {
				filter := req.URL.Query().Get("filter")
				if filter == auditFilter {
					return false
				}
				isContext := strings.Contains(req.URL.Path, "/context/")
				switch kind {
				case "anchor":
					if isContext {
						w.WriteHeader(404)
						return true
					}
				case "boundary":
					if isContext {
						json.NewEncoder(w).Encode(map[string]any{"event": events[0], "events_before": []any{}, "events_after": []any{}, "start": "p0", "end": "changed"})
						return true
					}
				case "deadline":
					x.f.now = x.f.now.Add(5 * time.Second)
					return false
				case "write":
					if isContext {
						os.Chmod(x.r.file.Name(), 0644)
					}
					return false
				}
				if isContext {
					return false
				}
				from := req.URL.Query().Get("from")
				page := map[string]any{"start": from, "chunk": []any{}}
				switch kind {
				case "continuity":
					page["start"] = "different"
				case "cycle":
					page["end"] = from
				case "filter":
					page["chunk"] = []any{membershipEvent(1, "@reader:example.org", "@reader:example.org", "join", "join")}
				case "count":
					items := make([]any, 1025)
					for i := range items {
						items[i] = events[0]
					}
					page["chunk"] = items
				default:
					return false
				}
				json.NewEncoder(w).Encode(page)
				return true
			}
			requireCode(t, x.recover(lines), "audit_room_unavailable")
			if x.r.Readiness() != roomUnavailable {
				t.Fatal("missing readiness diagnostic")
			}
			if x.f.c.ready || x.r.size != size || x.r.digest != old {
				t.Fatal("failed scan/write advanced coverage or left readiness open")
			}
		})
	}
}

// Completion requires the predecessor and retained read-back evidence,
// both scans, persistence and the original budget. These are primitive assertions;
// HTTP refusals and JWT release remain outside this package.
func TestReconciliationComplete(t *testing.T) {
	for _, kind := range []string{"valid", "predecessor", "non-audit", "membership", "write", "deadline", "replacement-budget", "foreign-candidate"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(2)
			x.events = events[:1]
			if err := x.recover(lines[:1]); err != nil {
				t.Fatal(err)
			}
			x.events = events
			if kind == "non-audit" || kind == "membership" {
				e := membershipEvent(1, "@reader:example.org", "@audit:example.org", "join", "leave")
				if kind == "non-audit" {
					e["type"] = "m.room.message"
				}
				x.events = append([]map[string]any{events[0], e}, events[1])
			}
			if kind == "predecessor" {
				x.events[0] = auditEvent(3, lines[0])
			}
			if kind == "write" {
				os.Chmod(x.r.file.Name(), 0644)
			}
			v := &Verified{position: Position{events[1]["event_id"].(string), room, 2, digest(lines[1])}, budget: x.f.budget, client: x.f.c}
			if kind == "foreign-candidate" {
				v.client = setup(t).c
			}
			if kind == "deadline" {
				x.f.now = x.f.now.Add(5 * time.Second)
			}
			if kind == "replacement-budget" {
				x.f.now = x.f.now.Add(5 * time.Second)
				x.f.budget = newBudget(x.f.now.Add(5*time.Second), func() time.Time { return x.f.now })
			}
			err := x.r.Complete(context.Background(), v, lines)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if !v.completed || len(x.r.state.Receipts) != 2 {
					t.Fatal("incomplete acknowledgement")
				}
				requireCode(t, x.r.Complete(context.Background(), v, lines), "audit_unavailable")
			} else {
				requireCode(t, err, "audit_unavailable")
				if v.completed || x.f.c.ready || len(x.r.state.Receipts) != 1 {
					t.Fatal("failed completion acknowledged")
				}
			}
		})
	}
}

// In a 24-line minimal chain fixture, both scans resume at the saved covered
// tail on every Complete and retain progress across restart. Each append has its
// own original budget; this does not exercise admission outcomes or stress load.
func TestIncrementalAppendBatch(t *testing.T) {
	x := newReconciliationFixture(t)
	lines, events := chain(24)
	x.events = events[:1]
	if err := x.recover(lines[:1]); err != nil {
		t.Fatal(err)
	}
	for n := 2; n <= len(lines); n++ {
		x.f.now = time.Now()
		x.f.budget = newBudget(x.f.now.Add(5*time.Second), func() time.Time { return x.f.now })
		x.events = events[:n]
		x.requests = nil
		v := &Verified{position: Position{events[n-1]["event_id"].(string), room, int64(n), digest(lines[n-1])}, budget: x.f.budget, client: x.f.c}
		if err := x.r.Complete(context.Background(), v, lines[:n]); err != nil {
			t.Fatal(n, err)
		}
		nonmember, member := false, false
		for _, request := range x.requests {
			if strings.Contains(request, "/messages?") {
				// Parse query via URL to avoid comparing encoded JSON strings.
				parsed, err := url.Parse(request)
				if err != nil {
					t.Fatal(err)
				}
				q := parsed.Query()
				if q.Get("dir") == "f" && q.Get("filter") == coverageFilters[0] {
					nonmember = true
					if q.Get("from") != fmt.Sprint("p", n-1) {
						t.Fatal("membership scan repeated covered history")
					}
					if q.Get("from") != fmt.Sprint("p", n-1) {
						t.Fatal("nonincremental scan")
					}
				}
				if q.Get("dir") == "f" && q.Get("filter") == coverageFilters[1] {
					member = true
				}
			}
		}
		if !nonmember || !member {
			t.Fatal("append omitted a coverage scan")
		}
	}
	x.restart(t)
	p, _ := x.r.Receipt()
	if p.Sequence != int64(len(lines)) || x.f.puts != 0 {
		t.Fatal("batch lost durable prefix")
	}
}

// A real PUT/read-back Attempt is still only a candidate: failed coverage cannot
// complete it, while the same exact original line with valid coverage completes.
func TestAttemptRequiresDurableCoverage(t *testing.T) {
	for _, kind := range []string{"valid", "scan", "write"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, _ := chain(1)
			delivery, err := x.f.c.Delivery(lines[0])
			if err != nil {
				t.Fatal(err)
			}
			v, err := delivery.Attempt(context.Background(), x.f.budget)
			if err != nil {
				t.Fatal(err)
			}
			if x.f.puts != 1 || x.f.gets != 1 || v.completed {
				t.Fatal("Attempt did not produce a read-back candidate")
			}
			if kind == "write" {
				os.Chmod(x.r.file.Name(), 0644)
			}
			if kind == "scan" {
				x.override = func(w http.ResponseWriter, req *http.Request) bool {
					if req.URL.Query().Get("filter") == coverageFilters[1] {
						w.WriteHeader(500)
						return true
					}
					return false
				}
			}
			err = x.r.Complete(context.Background(), v, lines)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if !v.completed {
					t.Fatal("valid completion failed")
				}
			} else {
				requireCode(t, err, "audit_unavailable")
				if v.completed || len(x.r.state.Receipts) != 0 || x.f.c.ready {
					t.Fatal("failed coverage acknowledged")
				}
			}
		})
	}
}

// Context filters apply to every before/after entry, not the anchor or state;
// changing volatile age is harmless, while a changed anchor cannot cover history.
func TestContextCoverageContract(t *testing.T) {
	for _, kind := range []string{"age", "after-filter", "before-filter", "state", "anchor-change"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if err := x.recover(lines); err != nil {
				t.Fatal(err)
			}
			x.override = func(w http.ResponseWriter, req *http.Request) bool {
				if !strings.Contains(req.URL.Path, "/context/") {
					return false
				}
				filter := req.URL.Query().Get("filter")
				if filter != coverageFilters[1] {
					return false
				}
				before, after := []any{}, []any{}
				state := []any{stateEvent("m.room.power_levels", "", map[string]any{})}
				event := auditEvent(1, lines[0])
				switch kind {
				case "age":
					event["unsigned"] = map[string]any{"age": 999}
				case "after-filter":
					after = append(after, event)
				case "before-filter":
					before = append(before, event)
				case "state":
					state = []any{map[string]any{"state_key": ""}}
				case "anchor-change":
					event["sender"] = "@reader:example.org"
				}
				json.NewEncoder(w).Encode(map[string]any{"event": event, "events_before": before, "events_after": after, "state": state, "start": "p0", "end": "p1"})
				return true
			}
			err := x.recover(lines)
			if kind == "age" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireCode(t, err, "audit_room_unavailable")
			}
		})
	}
}

// Closed/replaced/changed binding custody cannot be resurrected by recovery;
// restoring valid custody is handled by startup, never by this closed client.
func TestReconciliationBindingLifetime(t *testing.T) {
	for _, kind := range []string{"closed", "replaced", "changed"} {
		t.Run(kind, func(t *testing.T) {
			x := newReconciliationFixture(t)
			lines, events := chain(1)
			x.events = events
			if err := x.recover(lines); err != nil {
				t.Fatal(err)
			}
			path := x.f.c.cfg.BindingPath
			switch kind {
			case "closed":
				x.f.c.Close()
			case "replaced":
				raw, _ := os.ReadFile(path)
				os.Rename(path, path+".old")
				os.WriteFile(path, raw, 0600)
			case "changed":
				os.WriteFile(path, []byte("{}"), 0600)
			}
			x.requests = nil
			requireCode(t, x.recover(lines), "audit_room_unavailable")
			if x.f.c.ready || len(x.requests) != 0 {
				t.Fatal("lost binding custody reached network or reopened")
			}
		})
	}
}
