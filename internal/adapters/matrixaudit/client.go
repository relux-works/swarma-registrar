// Package matrixaudit supplies an isolated Matrix audit delivery primitive.
// It does not implement admission readiness, replay or Audit.Acknowledge.
package matrixaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
)

const EventType = "works.relux.registrar.audit.v0"

var unavailable = errors.New("audit_unavailable")

const roomUnavailable = RoomUnavailable
const roomPolicyInvalid = RoomPolicyInvalid
const roomHeadMismatch = RoomHeadMismatch

var configurationInvalid = errors.New("configuration_invalid")

// Config must come from the protected validated startup configuration.
// Room is a full room ID, never an alias or an arbitrary path component.
// Config is copied at startup. Token custody/loading belongs to the startup
// loader; pass its once-loaded bytes, never a reload callback or token path.
// BindingPath must be in the same protected directory as the local audit state.
type Config struct{ Origin, Room, User, BindingPath string }

// Client and its deliveries must be serialized by the caller's delivery lock.
type Client struct {
	cfg     Config
	token   string
	http    *http.Client
	binding *bindingFile
	ready   bool
}

// Budget retains a caller's original monotonic deadline across all steps. Callers
// must retain it through final release; no new budget may be made for retries.
type Budget struct {
	deadline time.Time
	now      func() time.Time
	valid    bool
}

func NewBudget(deadline time.Time) *Budget { return newBudget(deadline, time.Now) }
func newBudget(deadline time.Time, now func() time.Time) *Budget {
	remaining := deadline.Sub(now())
	return &Budget{deadline: deadline, now: now, valid: remaining > 0 && remaining <= 5*time.Second}
}
func (b *Budget) Remaining() time.Duration {
	if b == nil || b.now == nil || !b.valid {
		return 0
	}
	return b.deadline.Sub(b.now())
}
func (b *Budget) check(ctx context.Context) error {
	remaining := b.Remaining()
	if ctx.Err() != nil || remaining <= 0 || remaining > 5*time.Second {
		return unavailable
	}
	return nil
}

// Start authenticates and retains an exclusive durable binding before any send.
// nonempty is the validated local-chain state. On a fresh chain emptyRoom must
// verify empty audit history under this same budget; the caller supplies that scan.
func Start(ctx context.Context, cfg Config, token []byte, nonempty bool, emptyRoom func(context.Context, *Budget) error, b *Budget) (*Client, error) {
	c, err := newClient(cfg, token)
	if err != nil {
		return nil, err
	}
	if err = c.startup(ctx, b, nonempty, emptyRoom); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func newClient(cfg Config, token []byte) (*Client, error) {
	u, err := url.Parse(cfg.Origin)
	opaque, roomServer, roomOK := strings.Cut(strings.TrimPrefix(cfg.Room, "!"), ":")
	_, userServer, userOK := strings.Cut(cfg.User, ":")
	if !strings.HasPrefix(cfg.Room, "!") || !roomOK || opaque == "" || roomServer == "" || !userOK || roomServer != userServer {
		return nil, configurationInvalid
	}
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(cfg.Origin, "?#") || cfg.Room == "" || cfg.User == "" || len(token) == 0 || len(token) > 4096 {
		return nil, configurationInvalid
	}
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return nil, configurationInvalid
		}
	}
	tr := &transport{tls: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}}
	c := &Client{cfg: cfg, token: string(token), http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return unavailable }}}
	return c, nil
}
func (c *Client) Close() error {
	c.ready = false
	c.http.CloseIdleConnections()
	if c.binding != nil {
		err := c.binding.Close()
		c.binding = nil
		if err != nil {
			return roomUnavailable
		}
	}
	return nil
}

func component(s string) string { return url.PathEscape(s) }
func (c *Client) request(ctx context.Context, b *Budget, method string, parts []string, body []byte) (map[string]any, error) {
	value, err := c.requestJSON(ctx, b, method, parts, nil, body, 65536)
	if err != nil {
		return nil, unavailable
	}
	obj, ok := value.(map[string]any)
	if !ok || obj["errcode"] == "M_UNKNOWN_TOKEN" {
		return nil, unavailable
	}
	return obj, nil
}

type responseLimitKey struct{}

func (c *Client) requestJSON(ctx context.Context, b *Budget, method string, parts []string, query url.Values, body []byte, limit int64) (any, error) {
	if err := b.check(ctx); err != nil {
		return nil, unavailable
	}
	path := "/_matrix/client/v3"
	for _, p := range parts {
		path += "/" + component(p)
	}
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	ctx, cancel := context.WithDeadline(ctx, b.deadline)
	defer cancel()
	ctx = context.WithValue(ctx, responseLimitKey{}, limit)
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.Origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, unavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, unavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, unavailable
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(raw)) > limit || b.check(ctx) != nil {
		return nil, unavailable
	}
	value, err := ccj.Parse(raw, "audit_unavailable")
	if err != nil || b.check(ctx) != nil {
		return nil, unavailable
	}
	return value, nil
}

// Delivery snapshots the original persisted bytes. It can be retried only with
// this client's pinned identity and within the same caller budget. Creating this
// value does not persist or append a local record: the caller validates the chain.
type Delivery struct {
	c         *Client
	content   []byte
	line      []byte
	seq       int64
	hash, txn string
	budget    *Budget
}

func (c *Client) Delivery(persisted []byte) (*Delivery, error) {
	if !c.ready {
		return nil, unavailable
	}
	return c.delivery(persisted)
}
func (c *Client) delivery(persisted []byte) (*Delivery, error) {
	if len(persisted) < 2 || len(persisted) > 16384 || persisted[len(persisted)-1] != '\n' {
		return nil, unavailable
	}
	line := bytes.Clone(persisted[:len(persisted)-1])
	value, err := ccj.Parse(line, "audit_unavailable")
	if err != nil {
		return nil, unavailable
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, unavailable
	}
	seq, ok := obj["seq"].(int64)
	if !ok || seq < 1 || seq > 9007199254740991 {
		return nil, unavailable
	}
	canonical, err := ccj.Marshal(value, "audit_unavailable")
	if err != nil || !bytes.Equal(canonical, line) {
		return nil, unavailable
	}
	h := sha256.Sum256(persisted)
	hash := hex.EncodeToString(h[:])
	content, err := json.Marshal(map[string]any{"line": string(line), "seq": seq, "sha256": hash})
	if err != nil {
		return nil, unavailable
	}
	return &Delivery{c: c, content: content, line: line, seq: seq, hash: hash, txn: "audit-v0-" + hash}, nil
}
func validEventID(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "$") {
		return "", false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s[1:])
	return s, err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == s[1:]
}

type Position struct {
	EventID, RoomID string
	Sequence        int64
	SHA256          string
}

// Verified is a read-back candidate, not acknowledgement. Complete must run the
// interval scans, durable coverage write and final checks before success.
type Verified struct {
	client    *Client
	position  Position
	budget    *Budget
	completed bool
}

func (v *Verified) Position() Position { return v.position }
func (v *Verified) Complete(ctx context.Context, finish func(context.Context, Position, *Budget) error) error {
	if v.completed || v.budget.check(ctx) != nil || finish == nil {
		return unavailable
	}
	ctx, cancel := context.WithDeadline(ctx, v.budget.deadline)
	defer cancel()
	if finish(ctx, v.position, v.budget) != nil || v.budget.check(ctx) != nil {
		return unavailable
	}
	v.completed = true
	return nil
}
func (d *Delivery) Attempt(ctx context.Context, b *Budget) (*Verified, error) {
	if !d.c.ready || (d.budget != nil && d.budget != b) {
		return nil, unavailable
	}
	d.budget = b
	put, err := d.c.request(ctx, b, "PUT", []string{"rooms", d.c.cfg.Room, "send", EventType, d.txn}, d.content)
	if err != nil {
		return nil, unavailable
	}
	id, ok := validEventID(put["event_id"])
	if !ok {
		return nil, unavailable
	}
	event, err := d.c.request(ctx, b, "GET", []string{"rooms", d.c.cfg.Room, "event", id}, nil)
	if err != nil {
		return nil, unavailable
	}
	if !d.matches(event, id) || b.check(ctx) != nil {
		return nil, unavailable
	}
	return &Verified{client: d.c, position: Position{id, d.c.cfg.Room, d.seq, d.hash}, budget: b}, nil
}

func (d *Delivery) matches(event map[string]any, id string) bool {
	if event["event_id"] != id || event["room_id"] != d.c.cfg.Room || event["sender"] != d.c.cfg.User || event["type"] != EventType {
		return false
	}
	for _, key := range []string{"state_key", "redacts", "redacted_because"} {
		if _, present := event[key]; present {
			return false
		}
	}
	if u, present := event["unsigned"]; present {
		m, ok := u.(map[string]any)
		if !ok {
			return false
		}
		if _, present = m["redacted_because"]; present {
			return false
		}
	}
	content, ok := event["content"].(map[string]any)
	if !ok || len(content) != 3 {
		return false
	}
	line, ok := content["line"].(string)
	if !ok || !bytes.Equal([]byte(line), d.line) {
		return false
	}
	hash := sha256.Sum256(append([]byte(line), '\n'))
	if content["seq"] != d.seq || content["sha256"] != d.hash || hex.EncodeToString(hash[:]) != d.hash {
		return false
	}
	return true
}
