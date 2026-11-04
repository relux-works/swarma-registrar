// Package audittest supplies a policy-enforcing TLS homeserver for integration tests.
package audittest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-registrar/internal/adapters/matrixaudit"
)

const User = "@registrar-audit:example.org"
const Room = "!audit:example.org"
const Token = "test-audit-token"

// Server retains one ordered timeline and transaction table under a test mutex.
type Server struct {
	mu          sync.Mutex
	TLS         *httptest.Server
	events      []map[string]any
	txns        map[string]string
	mode        string
	puts, reads int
	hook        func()
	device      string
}

func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{txns: map[string]string{}, device: "DEVICE"}
	s.TLS = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.TLS.Close)
	return s
}
func (s *Server) Config(binding string) matrixaudit.Config {
	roots := x509.NewCertPool()
	roots.AddCert(s.TLS.Certificate())
	return matrixaudit.Config{Origin: s.TLS.URL, Room: Room, User: User, BindingPath: binding, Roots: roots}
}
func (s *Server) Set(mode string, hook func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode, s.hook = mode, hook
}
func (s *Server) Device(device string) { s.mu.Lock(); defer s.mu.Unlock(); s.device = device }
func (s *Server) Counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events), s.puts, s.reads
}
func (s *Server) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for _, e := range s.events {
		out = append(out, e["content"].(map[string]any)["line"].(string)+"\n")
	}
	return out
}
func state() []any {
	e := func(typ, key string, c map[string]any) any {
		return map[string]any{"type": typ, "state_key": key, "sender": User, "content": c}
	}
	return []any{
		e("m.room.create", "", map[string]any{"room_version": "11", "m.federate": false}),
		e("m.room.join_rules", "", map[string]any{"join_rule": "invite"}),
		e("m.room.history_visibility", "", map[string]any{"history_visibility": "shared"}),
		e("m.room.guest_access", "", map[string]any{"guest_access": "forbidden"}),
		e("m.room.power_levels", "", map[string]any{"users_default": 0, "events_default": 101, "state_default": 101, "invite": 101, "kick": 101, "ban": 101, "redact": 101, "users": map[string]any{User: 100}, "events": map[string]any{matrixaudit.EventType: 100}}),
		e("m.room.member", User, map[string]any{"membership": "join"}),
	}
}
func match(e map[string]any, filter string) bool {
	switch filter {
	case `{"types":["works.relux.registrar.audit.v0"]}`:
		return e["type"] == matrixaudit.EventType
	case `{"not_types":["m.room.member"]}`:
		return e["type"] != "m.room.member"
	case `{"types":["m.room.member"]}`:
		return e["type"] == "m.room.member"
	}
	return false
}
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+Token && auth != "Bearer reader-token" {
		w.WriteHeader(401)
		return
	}
	path := r.URL.Path
	if r.Method == "PUT" {
		if auth != "Bearer "+Token || !strings.Contains(path, "/send/"+matrixaudit.EventType+"/") {
			w.WriteHeader(403)
			return
		}
		s.puts++
		if s.mode == "put" {
			w.WriteHeader(503)
			return
		}
		var content map[string]any
		if json.NewDecoder(r.Body).Decode(&content) != nil {
			w.WriteHeader(400)
			return
		}
		line, _ := content["line"].(string)
		h := sha256.Sum256([]byte(line + "\n"))
		if content["sha256"] != hex.EncodeToString(h[:]) || !strings.HasSuffix(path, "audit-v0-"+hex.EncodeToString(h[:])) {
			w.WriteHeader(400)
			return
		}
		id := s.txns[path]
		if id == "" {
			id = "$" + base64.RawURLEncoding.EncodeToString(h[:])
			s.txns[path] = id
			s.events = append(s.events, map[string]any{"event_id": id, "room_id": Room, "type": matrixaudit.EventType, "sender": User, "content": content})
		}
		reply(map[string]any{"event_id": id})
		return
	}
	switch {
	case strings.HasSuffix(path, "/whoami"):
		reply(map[string]any{"user_id": User, "device_id": s.device})
	case strings.HasSuffix(path, "/state"):
		if s.mode == "policy" {
			reply([]any{})
			return
		}
		reply(state())
	case strings.Contains(path, "/event/"):
		s.reads++
		if s.hook != nil {
			hook := s.hook
			s.hook = nil
			hook()
		}
		if s.mode == "readback" {
			w.WriteHeader(503)
			return
		}
		id := path[strings.LastIndex(path, "/")+1:]
		for _, e := range s.events {
			if e["event_id"] == id {
				if s.mode == "bytes" {
					raw, _ := json.Marshal(e)
					var copy map[string]any
					json.Unmarshal(raw, &copy)
					copy["content"].(map[string]any)["line"] = "different"
					reply(copy)
					return
				}
				reply(e)
				return
			}
		}
		w.WriteHeader(404)
	case strings.Contains(path, "/context/"):
		id := path[strings.LastIndex(path, "/")+1:]
		for i, e := range s.events {
			if e["event_id"] == id {
				before := []any{}
				start := i
				if r.URL.Query().Get("limit") == "1024" && i > 0 {
					before = append(before, s.events[i-1])
					start = i - 1
				}
				if s.mode == "anchor" {
					e = map[string]any{"event_id": id}
				}
				reply(map[string]any{"event": e, "events_before": before, "events_after": []any{}, "state": []any{}, "start": fmt.Sprint("p", start), "end": fmt.Sprint("p", i+1)})
				return
			}
		}
		w.WriteHeader(404)
	case strings.HasSuffix(path, "/messages"):
		filter := r.URL.Query().Get("filter")
		if s.mode == "head" && r.URL.Query().Get("dir") == "b" && filter == `{"types":["works.relux.registrar.audit.v0"]}` && len(s.events) > 0 {
			reply(map[string]any{"start": fmt.Sprint("p", len(s.events)), "chunk": []any{map[string]any{"type": matrixaudit.EventType}}})
			return
		}
		forward := r.URL.Query().Get("dir") == "f"
		if s.mode == "scan" && forward {
			w.WriteHeader(503)
			return
		}
		from := r.URL.Query().Get("from")
		pos := len(s.events)
		if from != "" {
			var err error
			pos, err = strconv.Atoi(strings.TrimPrefix(from, "p"))
			if err != nil || pos < 0 || pos > len(s.events) {
				w.WriteHeader(400)
				return
			}
		} else {
			from = fmt.Sprint("p", pos)
		}
		upper := len(s.events)
		if to := r.URL.Query().Get("to"); to != "" {
			upper, _ = strconv.Atoi(strings.TrimPrefix(to, "p"))
		}
		chunk := []any{}
		if forward {
			for i := pos; i < upper; i++ {
				if match(s.events[i], filter) {
					chunk = append(chunk, s.events[i])
				}
			}
		} else {
			for i := pos - 1; i >= 0; i-- {
				if match(s.events[i], filter) {
					chunk = append(chunk, s.events[i])
				}
			}
		}
		reply(map[string]any{"start": from, "chunk": chunk})
	default:
		w.WriteHeader(404)
	}
}
