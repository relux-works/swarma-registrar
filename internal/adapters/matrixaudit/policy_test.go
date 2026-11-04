package matrixaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func stateEvent(typ, key string, content map[string]any) map[string]any {
	return map[string]any{"type": typ, "state_key": key, "sender": "@audit:example.org", "content": content}
}
func validState() []any {
	return []any{
		stateEvent("m.room.create", "", map[string]any{"room_version": "11", "m.federate": false}),
		stateEvent("m.room.join_rules", "", map[string]any{"join_rule": "invite"}),
		stateEvent("m.room.history_visibility", "", map[string]any{"history_visibility": "shared"}),
		stateEvent("m.room.guest_access", "", map[string]any{"guest_access": "forbidden"}),
		stateEvent("m.room.power_levels", "", map[string]any{"users_default": 0, "events_default": 101, "state_default": 101, "invite": 101, "kick": 101, "ban": 101, "redact": 101, "users": map[string]any{"@audit:example.org": 100, "@reader:example.org": 0}, "events": map[string]any{EventType: 100}}),
		stateEvent("m.room.member", "@audit:example.org", map[string]any{"membership": "join"}),
		map[string]any{"type": "m.room.member", "state_key": "@reader:example.org", "sender": "@reader:example.org", "content": map[string]any{"membership": "join"}},
	}
}
func content(f *fixture, n int) map[string]any {
	return f.state[n].(map[string]any)["content"].(map[string]any)
}
func startFixture(f *fixture) error {
	return f.c.startup(context.Background(), f.budget, false, func(context.Context, *Budget) error { return nil })
}

// Each isolated parsed restriction fails before binding or writes; the same fixture
// with the final locked policy passes. This proves policy observation, not live enforcement.
func TestStartupPolicy(t *testing.T) {
	cases := map[string]func(*fixture){
		"invalid-membership": func(f *fixture) { content(f, 6)["membership"] = "invalid" },
		"missing-users":      func(f *fixture) { delete(content(f, 4), "users") },
		"missing-events":     func(f *fixture) { delete(content(f, 4), "events") },
		"string-user":        func(f *fixture) { content(f, 4)["users"].(map[string]any)["@reader:example.org"] = "0" },
		"federation":         func(f *fixture) { content(f, 0)["m.federate"] = true },
		"missing-federation": func(f *fixture) { delete(content(f, 0), "m.federate") },
		"version":            func(f *fixture) { content(f, 0)["room_version"] = "12" },
		"missing-version":    func(f *fixture) { delete(content(f, 0), "room_version") },
		"create-key":         func(f *fixture) { f.state[0].(map[string]any)["state_key"] = "wrong" },
		"creator":            func(f *fixture) { f.state[0].(map[string]any)["sender"] = "@reader:example.org" },
		"predecessor":        func(f *fixture) { content(f, 0)["predecessor"] = nil },
		"join-rule":          func(f *fixture) { content(f, 1)["join_rule"] = "public" },
		"history":            func(f *fixture) { content(f, 2)["history_visibility"] = "joined" },
		"guest":              func(f *fixture) { content(f, 3)["guest_access"] = "can_join" },
		"missing-guest":      func(f *fixture) { f.state = append(f.state[:3], f.state[4:]...) },
		"encryption":         func(f *fixture) { f.state = append(f.state, stateEvent("m.room.encryption", "", map[string]any{})) },
		"tombstone":          func(f *fixture) { f.state = append(f.state, stateEvent("m.room.tombstone", "", map[string]any{})) },
		"not-joined":         func(f *fixture) { content(f, 5)["membership"] = "leave" },
		"foreign-joined": func(f *fixture) {
			f.state = append(f.state, stateEvent("m.room.member", "@reader:elsewhere.org", map[string]any{"membership": "join"}))
		},
		"foreign-invited": func(f *fixture) {
			f.state = append(f.state, stateEvent("m.room.member", "@reader:elsewhere.org", map[string]any{"membership": "invite"}))
		},
		"another-writer":  func(f *fixture) { content(f, 4)["users"].(map[string]any)["@reader:example.org"] = 100 },
		"absent-writer":   func(f *fixture) { content(f, 4)["users"].(map[string]any)["@absent:example.org"] = 1 },
		"creator-high":    func(f *fixture) { content(f, 4)["users"].(map[string]any)["@audit:example.org"] = 101 },
		"creator-low":     func(f *fixture) { content(f, 4)["users"].(map[string]any)["@audit:example.org"] = 99 },
		"extra-override":  func(f *fixture) { content(f, 4)["events"].(map[string]any)["m.room.message"] = 101 },
		"audit-threshold": func(f *fixture) { content(f, 4)["events"].(map[string]any)[EventType] = 99 },
	}
	for _, field := range []string{"users_default", "events_default", "state_default", "invite", "kick", "ban", "redact"} {
		cases[field] = func(f *fixture) { content(f, 4)[field] = 1 }
		cases["missing-"+field] = func(f *fixture) { delete(content(f, 4), field) }
		cases["string-"+field] = func(f *fixture) { content(f, 4)[field] = "101" }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupServer(t)
			change(f)
			requireCode(t, startFixture(f), "audit_room_policy_invalid")
			if f.c.ready || f.puts != 0 {
				t.Fatal("invalid policy opened delivery")
			}
			if _, err := os.Stat(f.c.cfg.BindingPath); !os.IsNotExist(err) {
				t.Fatal("invalid policy wrote binding")
			}
			f.state = validState()
			if err := startFixture(f); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(f.paths[0], "/whoami") || !strings.HasSuffix(f.paths[1], "/state") {
				t.Fatal("startup order")
			}
		})
	}
}

// Missing/wrong-type identity fields are unavailable evidence; a present user
// mismatch is a parsed violation. Changed devices remain unavailable (binding tests).
func TestIdentityEvidence(t *testing.T) {
	for _, field := range []string{"user_id", "device_id"} {
		for _, value := range []any{nil, 1, true, []any{}, map[string]any{}} {
			t.Run(fmt.Sprint(field, value), func(t *testing.T) {
				f := setupServer(t)
				who := f.who.(map[string]any)
				if value == nil {
					delete(who, field)
				} else {
					who[field] = value
				}
				requireCode(t, startFixture(f), "audit_room_unavailable")
				if len(f.paths) != 1 || f.puts != 0 {
					t.Fatal("continued without identity")
				}
				who["user_id"] = "@audit:example.org"
				who["device_id"] = "DEVICE"
				if err := startFixture(f); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	f := setupServer(t)
	f.who.(map[string]any)["user_id"] = "@other:example.org"
	requireCode(t, startFixture(f), "audit_room_policy_invalid")
	f.who.(map[string]any)["user_id"] = "@audit:example.org"
	if err := startFixture(f); err != nil {
		t.Fatal(err)
	}
}

// The fake applies final power thresholds to writes/redactions: rejecting all
// operations cannot pass because the audit identity must be able to append.
func TestPolicyEnforcementControl(t *testing.T) {
	f := setup(t)
	for _, op := range []struct{ token, kind string }{
		{"reader-token", EventType}, {"reader-token", "m.room.message"},
		{"reader-token", "m.room.redaction"}, {"secret-token", "m.room.redaction"},
	} {
		f.c.token = op.token
		parts := []string{"rooms", room, "send", op.kind, "control"}
		if op.kind == "m.room.redaction" {
			parts = []string{"rooms", room, "redact", eventID, "control"}
		}
		_, err := f.c.request(context.Background(), f.budget, "PUT", parts, []byte(`{}`))
		requireCode(t, err, "audit_unavailable")
		if f.puts != 0 {
			t.Fatal("forbidden operation created event")
		}
	}
	f.c.token = "secret-token"
	if _, err := f.attempt(); err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 || len(f.events) != 1 {
		t.Fatal("valid writer did not append exactly once")
	}
}
func policyPermission(state []any, user, typ string) int {
	p := state[4].(map[string]any)["content"].(map[string]any)
	level := 0
	if v, ok := p["users"].(map[string]any)[user].(int); ok {
		level = v
	}
	required := p["events_default"].(int)
	if v, ok := p["events"].(map[string]any)[typ].(int); ok {
		required = v
	}
	if typ == "m.room.redaction" {
		required = p["redact"].(int)
	}
	if level < required {
		return 403
	}
	return 200
}

// Bounded complete state has strict byte/event limits, duplicate-safe parsing and
// a shared startup deadline across whoami and state; exact limits remain usable.
func TestStateEvidenceBounds(t *testing.T) {
	for _, body := range [][]byte{[]byte(`{}`), []byte(`[`), []byte(`[{"type":"x","type":"y"}]`), {0xff}} {
		t.Run(fmt.Sprint(body), func(t *testing.T) {
			f := setupServer(t)
			f.stateBody = body
			requireCode(t, startFixture(f), "audit_room_unavailable")
			f.stateBody = nil
			if err := startFixture(f); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, size := range []int{4*1024*1024 + 1, 4 * 1024 * 1024} {
		t.Run(fmt.Sprint("bytes", size), func(t *testing.T) {
			f := setupServer(t)
			raw, _ := json.Marshal(f.state)
			f.stateBody = append(raw, bytes.Repeat([]byte(" "), size-len(raw))...)
			err := startFixture(f)
			if size > 4*1024*1024 {
				requireCode(t, err, "audit_room_unavailable")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, count := range []int{1025, 1024} {
		t.Run(fmt.Sprint("events", count), func(t *testing.T) {
			f := setupServer(t)
			for len(f.state) < count {
				f.state = append(f.state, stateEvent("custom", fmt.Sprint(len(f.state)), map[string]any{}))
			}
			err := startFixture(f)
			if count > 1024 {
				requireCode(t, err, "audit_room_unavailable")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, delta := range []time.Duration{3 * time.Second, 3*time.Second - 1} {
		t.Run(delta.String(), func(t *testing.T) {
			f := setupServer(t)
			f.advanceWho = 2 * time.Second
			f.advanceState = delta
			err := startFixture(f)
			if delta == 3*time.Second {
				requireCode(t, err, "audit_room_unavailable")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
	f := setupServer(t)
	f.stateStatus = 503
	requireCode(t, startFixture(f), "audit_room_unavailable")
	f.stateStatus = 200
	if err := startFixture(f); err != nil {
		t.Fatal(err)
	}
}

func headEvent() map[string]any {
	h := sha256.Sum256(original)
	return map[string]any{"event_id": eventID, "room_id": room, "sender": "@audit:example.org", "type": EventType, "content": map[string]any{"line": string(original[:len(original)-1]), "seq": 1, "sha256": fmt.Sprintf("%x", h)}}
}
func advancedHeadEvent() map[string]any {
	e := headEvent()
	raw := []byte("{\"seq\":2}\n")
	h := sha256.Sum256(raw)
	e["event_id"] = "$" + base64.RawURLEncoding.EncodeToString(h[:])
	e["content"] = map[string]any{"line": string(raw[:len(raw)-1]), "seq": 2, "sha256": fmt.Sprintf("%x", h)}
	return e
}
func headPage(events ...any) map[string]any {
	if events == nil {
		events = []any{}
	}
	return map[string]any{"start": "tail", "chunk": events}
}

// Fresh filtered reads compare exact bytes, identity and receipt, including a
// second call after remote advancement. This primitive does not prove coverage.
func TestHeadReconciliation(t *testing.T) {
	for _, mutate := range []string{"empty", "ahead", "redacted", "sender", "line", "id"} {
		t.Run(mutate, func(t *testing.T) {
			f := setup(t)
			e := headEvent()
			h := sha256.Sum256(original)
			p := Position{eventID, room, 1, fmt.Sprintf("%x", h)}
			switch mutate {
			case "empty":
			case "ahead":
				e = advancedHeadEvent()
			case "redacted":
				e["unsigned"] = map[string]any{"redacted_because": map[string]any{}}
			case "sender":
				e["sender"] = "@reader:example.org"
			case "line":
				e["content"].(map[string]any)["line"] = `{"seq":2}`
			case "id":
				e["event_id"] = "$wrong"
			}
			page := headPage(e)
			if mutate == "empty" {
				page = headPage()
			}
			f.pages = []map[string]any{page, headPage(headEvent()), headPage(e)}
			requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_head_mismatch")
			if err := f.c.ReconcileHead(context.Background(), f.budget, &p, original); err != nil {
				t.Fatal(err)
			}
			if mutate != "empty" {
				requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_head_mismatch")
			}
			for _, filter := range f.filters {
				if filter != `{"types":["works.relux.registrar.audit.v0"]}` {
					t.Fatal("wrong filter")
				}
			}
			if f.puts != 0 {
				t.Fatal("head mismatch sent")
			}
		})
	}
	f := setup(t)
	f.pages = []map[string]any{headPage(headEvent()), headPage()}
	requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, nil, nil), "audit_room_head_mismatch")
	if err := f.c.ReconcileHead(context.Background(), f.budget, nil, nil); err != nil {
		t.Fatal(err)
	}
}

// Empty intermediate pages are followed with retained tokens; ignored filters,
// malformed pages and looping continuity never become an empty-room proof.
func TestHeadPagination(t *testing.T) {
	for _, bad := range []map[string]any{
		{"chunk": []any{}}, {"start": "tail", "chunk": []any{stateEvent("m.room.member", "x", map[string]any{})}},
		{"start": "tail", "chunk": []any{}, "end": "tail"},
	} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			f := setup(t)
			f.pages = []map[string]any{bad}
			requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, nil, nil), "audit_room_unavailable")
			f.page = 0
			f.pages = []map[string]any{{"start": "tail", "end": "older", "chunk": []any{}}, {"start": "older", "chunk": []any{}}}
			if err := f.c.ReconcileHead(context.Background(), f.budget, nil, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Policy is observed afresh on repeated calls; restoration here is only a policy
// observation and cannot clear the future persistent timeline fence.
func TestRepeatedPolicyObservation(t *testing.T) {
	f := setup(t)
	content(f, 4)["redact"] = 0
	requireCode(t, f.c.CheckPolicy(context.Background(), f.budget), "audit_room_policy_invalid")
	f.state = validState()
	if err := f.c.CheckPolicy(context.Background(), f.budget); err != nil {
		t.Fatal(err)
	}
}

// The complete filtered page is checked, including entries after a valid head;
// byte/event caps and token continuity fail without sending or altering binding.
func TestHeadEvidenceBounds(t *testing.T) {
	for _, kind := range []string{"trailing-filter", "oversize", "too-many", "continuity", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			h := sha256.Sum256(original)
			p := Position{eventID, room, 1, fmt.Sprintf("%x", h)}
			page := headPage(headEvent())
			f.pages = []map[string]any{page}
			switch kind {
			case "trailing-filter":
				page["chunk"] = []any{headEvent(), stateEvent("m.room.member", "x", map[string]any{})}
			case "oversize":
				page["padding"] = strings.Repeat("x", pageBytes)
			case "too-many":
				chunk := make([]any, 1025)
				for i := range chunk {
					chunk[i] = headEvent()
				}
				page["chunk"] = chunk
			case "continuity":
				f.pages = []map[string]any{{"start": "tail", "end": "older", "chunk": []any{}}, {"start": "different", "chunk": []any{headEvent()}}}
			case "deadline":
				f.now = f.now.Add(5 * time.Second)
			}
			before, err := os.ReadFile(f.c.cfg.BindingPath)
			if err != nil {
				t.Fatal(err)
			}
			requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_unavailable")
			after, err := os.ReadFile(f.c.cfg.BindingPath)
			if err != nil || !bytes.Equal(before, after) || f.puts != 0 {
				t.Fatal("head check mutated custody")
			}
			f.page = 0
			f.pages = []map[string]any{headPage(headEvent())}
			f.budget = newBudget(f.now.Add(5*time.Second), func() time.Time { return f.now })
			if err := f.c.ReconcileHead(context.Background(), f.budget, &p, original); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A room-scoped event may omit redundant room metadata; local receipt mismatch
// and conflicting served room metadata still fail the exact-head comparison.
func TestHeadRoomAndReceipt(t *testing.T) {
	f := setup(t)
	h := sha256.Sum256(original)
	p := Position{eventID, room, 1, fmt.Sprintf("%x", h)}
	e := headEvent()
	e["room_id"] = "!other:example.org"
	f.pages = []map[string]any{headPage(e), headPage(headEvent())}
	requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_head_mismatch")
	p.SHA256 = strings.Repeat("0", 64)
	requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_head_mismatch")
	p.SHA256 = fmt.Sprintf("%x", h)
	delete(f.pages[1]["chunk"].([]any)[0].(map[string]any), "room_id")
	if err := f.c.ReconcileHead(context.Background(), f.budget, &p, original); err != nil {
		t.Fatal(err)
	}
}

// Duplicate or malformed state is unavailable evidence rather than a parsed
// policy violation; a complete state with the same required entries passes.
func TestStateStructure(t *testing.T) {
	for _, bad := range []string{"duplicate", "content", "sender", "type", "key", "element"} {
		t.Run(bad, func(t *testing.T) {
			f := setupServer(t)
			switch bad {
			case "duplicate":
				f.state = append(f.state, f.state[0])
			case "content":
				f.state[0].(map[string]any)["content"] = nil
			case "sender":
				delete(f.state[0].(map[string]any), "sender")
			case "type":
				f.state[0].(map[string]any)["type"] = 3
			case "key":
				f.state[0].(map[string]any)["state_key"] = 3
			case "element":
				f.state[0] = nil
			}
			requireCode(t, startFixture(f), "audit_room_unavailable")
			f.state = validState()
			if err := startFixture(f); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Arbitrary dot components and aliases never reach authenticated transport;
// valid opaque room IDs containing slashes/dots remain one escaped component.
func TestRoomComponentContract(t *testing.T) {
	f := setupServer(t)
	for _, roomID := range []string{".", "..", "#audit:example.org", "!:example.org", "!audit:other.org"} {
		cfg := f.c.cfg
		cfg.Room = roomID
		_, err := newClient(cfg, []byte("secret-token"))
		requireCode(t, err, "configuration_invalid")
	}
	f.c.cfg.Room = "!x/../y:example.org"
	if err := startFixture(f); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.paths[1], "%21x%2F..%2Fy:example.org/state") {
		t.Fatal("room component changed path structure")
	}
}

// The successful first comparison is not a cache: remote advancement is observed
// on the very next call, without restarting the client or extending its budget.
func TestFreshHeadEachComparison(t *testing.T) {
	f := setup(t)
	h := sha256.Sum256(original)
	p := Position{eventID, room, 1, fmt.Sprintf("%x", h)}
	changed := advancedHeadEvent()
	f.pages = []map[string]any{headPage(headEvent()), headPage(changed), headPage(headEvent())}
	if err := f.c.ReconcileHead(context.Background(), f.budget, &p, original); err != nil {
		t.Fatal(err)
	}
	requireCode(t, f.c.ReconcileHead(context.Background(), f.budget, &p, original), "audit_room_head_mismatch")
	if err := f.c.ReconcileHead(context.Background(), f.budget, &p, original); err != nil {
		t.Fatal(err)
	}
	if f.page != 3 {
		t.Fatal("a comparison reused stale evidence")
	}
}

// Explicit null evidence is unavailable, while an empty but string-valued user
// differs from the pinned user. Diagnostics remain typed and identity-only calls stop.
func TestNullIdentityEvidence(t *testing.T) {
	for _, field := range []string{"user_id", "device_id"} {
		f := setupServer(t)
		f.who.(map[string]any)[field] = nil
		err := startFixture(f)
		requireCode(t, err, "audit_room_unavailable")
		if _, ok := err.(ReadinessCode); !ok {
			t.Fatal("untyped readiness diagnostic")
		}
		f.who = map[string]any{"user_id": "@audit:example.org", "device_id": "DEVICE"}
		if err := startFixture(f); err != nil {
			t.Fatal(err)
		}
	}
	f := setupServer(t)
	f.who.(map[string]any)["user_id"] = ""
	requireCode(t, startFixture(f), "audit_room_policy_invalid")
	f.who.(map[string]any)["user_id"] = "@audit:example.org"
	if err := startFixture(f); err != nil {
		t.Fatal(err)
	}
}
