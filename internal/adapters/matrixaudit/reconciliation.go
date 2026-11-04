package matrixaudit

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
)

var coverageFilters = [2]string{`{"not_types":["m.room.member"]}`, `{"types":["m.room.member"]}`}

const auditFilter = `{"types":["works.relux.registrar.audit.v0"]}`

type historyPage struct {
	events     []map[string]any
	start, end string
}

func filterOK(e map[string]any, filter string) bool {
	typ, ok := e["type"].(string)
	if !ok || typ == "" {
		return false
	}
	switch filter {
	case auditFilter:
		return typ == EventType
	case coverageFilters[0]:
		return typ != "m.room.member"
	default:
		return typ == "m.room.member"
	}
}
func timeline(value any, filter string) ([]map[string]any, error) {
	array, ok := value.([]any)
	if !ok || len(array) > pageEvents {
		return nil, roomUnavailable
	}
	out := make([]map[string]any, 0, len(array))
	for _, v := range array {
		e, ok := v.(map[string]any)
		if !ok || !filterOK(e, filter) {
			return nil, roomUnavailable
		}
		out = append(out, e)
	}
	return out, nil
}
func (c *Client) history(ctx context.Context, b *Budget, filter, dir, from string, to ...string) (historyPage, error) {
	q := url.Values{"dir": {dir}, "limit": {"1024"}, "filter": {filter}}
	if from != "" {
		q.Set("from", from)
	}
	if len(to) > 0 && to[0] != "" {
		q.Set("to", to[0])
	}
	value, err := c.requestJSON(ctx, b, "GET", []string{"rooms", c.cfg.Room, "messages"}, q, nil, pageBytes)
	if err != nil {
		return historyPage{}, roomUnavailable
	}
	m, ok := value.(map[string]any)
	if !ok {
		return historyPage{}, roomUnavailable
	}
	start, ok := m["start"].(string)
	if !ok || start == "" || (from != "" && from != start) {
		return historyPage{}, roomUnavailable
	}
	events, err := timeline(m["chunk"], filter)
	if err != nil {
		return historyPage{}, err
	}
	end := ""
	if v, present := m["end"]; present {
		end, ok = v.(string)
		if !ok || end == "" || end == start {
			return historyPage{}, roomUnavailable
		}
	}
	return historyPage{events, start, end}, nil
}
func (c *Client) contextAt(ctx context.Context, b *Budget, id, filter string, limit string) (map[string]any, []map[string]any, string, string, error) {
	value, err := c.requestJSON(ctx, b, "GET", []string{"rooms", c.cfg.Room, "context", id}, url.Values{"filter": {filter}, "limit": {limit}}, nil, pageBytes)
	if err != nil {
		return nil, nil, "", "", roomUnavailable
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, nil, "", "", roomUnavailable
	}
	before, err := timeline(m["events_before"], filter)
	if err != nil {
		return nil, nil, "", "", err
	}
	after, err := timeline(m["events_after"], filter)
	if err != nil || len(before)+len(after) > pageEvents {
		return nil, nil, "", "", roomUnavailable
	}
	anchor, ok := m["event"].(map[string]any)
	if !ok || anchor["event_id"] != id {
		return nil, nil, "", "", roomUnavailable
	}
	start, sOK := m["start"].(string)
	end, eOK := m["end"].(string)
	if !sOK || !eOK || start == "" || end == "" || start == end {
		return nil, nil, "", "", roomUnavailable
	}
	// The anchor and optional context state are not filter projections.
	if state, present := m["state"]; present {
		items, ok := state.([]any)
		if !ok || len(items)+len(before)+len(after)+1 > pageEvents {
			return nil, nil, "", "", roomUnavailable
		}
		for _, v := range items {
			s, ok := v.(map[string]any)
			if !ok {
				return nil, nil, "", "", roomUnavailable
			}
			_, keyOK := s["state_key"].(string)
			typ, typeOK := s["type"].(string)
			sender, senderOK := s["sender"].(string)
			_, contentOK := s["content"].(map[string]any)
			if !keyOK || !typeOK || typ == "" || !senderOK || sender == "" || !contentOK {
				return nil, nil, "", "", roomUnavailable
			}
		}
	}
	if limit == "0" && (len(before) != 0 || len(after) != 0) {
		return nil, nil, "", "", roomUnavailable
	}
	return anchor, before, start, end, nil
}
func (r *Reconciliation) local(ctx context.Context, b *Budget, lines [][]byte) ([]*Delivery, error) {
	out := make([]*Delivery, len(lines))
	prev := strings.Repeat("0", 64)
	for i, line := range lines {
		if b.check(ctx) != nil {
			return nil, roomUnavailable
		}
		d, err := r.c.delivery(line)
		if err != nil || d.seq != int64(i+1) {
			return nil, roomHeadMismatch
		}
		v, err := ccj.Parse(d.line, "audit_room_head_mismatch")
		if err != nil || v.(map[string]any)["prev_hash"] != prev {
			return nil, roomHeadMismatch
		}
		if i < len(r.state.Receipts) && (r.state.Receipts[i].Sequence != d.seq || r.state.Receipts[i].SHA256 != d.hash || r.state.Receipts[i].RoomID != r.c.cfg.Room) {
			return nil, roomHeadMismatch
		}
		out[i] = d
		prev = d.hash
	}
	if len(lines) < len(r.state.Receipts) {
		return nil, roomHeadMismatch
	}
	return out, nil
}
func (r *Reconciliation) match(e map[string]any, d *Delivery, id string) bool {
	if e == nil {
		return false
	}
	if _, present := e["room_id"]; !present {
		e["room_id"] = r.c.cfg.Room
	}
	return d.matches(e, id)
}

// Recover walks every remote audit event, reconstructs receipts and covers the
// unchecked tail before persisting the replay start. It never sends a line.
func (r *Reconciliation) Recover(ctx context.Context, b *Budget, lines [][]byte) error {
	if r.bad || !r.bound() || r.state.Fence != "" {
		return r.failure(roomUnavailable)
	}
	local, err := r.local(ctx, b, lines)
	if err != nil {
		return r.failure(ReadinessCode(err.Error()))
	}
	receipts := []Position{}
	from := ""
	seen := map[string]bool{}
	tail := ""
	expected := int64(-1)
	ids := map[string]bool{}
	for {
		page, err := r.c.history(ctx, b, auditFilter, "b", from)
		if err != nil {
			return r.failure(roomUnavailable)
		}
		if tail == "" {
			tail = page.start
		}
		for _, e := range page.events {
			content, _ := e["content"].(map[string]any)
			seq, ok := content["seq"].(int64)
			id, idOK := validEventID(e["event_id"])
			if !ok || !idOK || ids[id] || seq < 1 || seq > int64(len(local)) || (expected != -1 && seq != expected) || !r.match(e, local[seq-1], id) {
				return r.fence(ctx, b, roomHeadMismatch, id)
			}
			if seq <= int64(len(r.state.Receipts)) && r.state.Receipts[seq-1].EventID != id {
				return r.fence(ctx, b, roomHeadMismatch, id)
			}
			ids[id] = true
			receipts = append(receipts, Position{id, r.c.cfg.Room, seq, local[seq-1].hash})
			expected = seq - 1
		}
		if page.end == "" {
			break
		}
		if seen[page.end] {
			return r.failure(roomUnavailable)
		}
		seen[page.start] = true
		seen[page.end] = true
		from = page.end
	}
	if (expected != -1 && expected != 0) || len(receipts) < len(r.state.Receipts) {
		return r.fence(ctx, b, roomHeadMismatch, "")
	}
	for i, j := 0, len(receipts)-1; i < j; i, j = i+1, j-1 {
		receipts[i], receipts[j] = receipts[j], receipts[i]
	}
	return r.cover(ctx, b, local, receipts, tail)
}

// Complete finalizes any issued, refused or replay read-back using the same
// Budget captured by Attempt. No admission result or token is produced here.
func (r *Reconciliation) Complete(ctx context.Context, v *Verified, lines [][]byte) error {
	if v == nil || v.client != r.c {
		r.failure(roomUnavailable)
		return unavailable
	}
	err := v.Complete(ctx, func(ctx context.Context, p Position, b *Budget) error {
		if r.bad || !r.bound() || r.state.Fence != "" {
			return r.failure(roomUnavailable)
		}
		local, err := r.local(ctx, b, lines)
		if err != nil {
			return r.failure(ReadinessCode(err.Error()))
		}
		n := len(r.state.Receipts)
		if n >= len(local) || p.Sequence != int64(n+1) || p.RoomID != r.c.cfg.Room || p.SHA256 != local[n].hash {
			return r.failure(roomHeadMismatch)
		}
		if err = r.predecessor(ctx, b, p, local); err != nil {
			return err
		}
		receipts := append(append([]Position{}, r.state.Receipts...), p)
		page, err := r.c.history(ctx, b, auditFilter, "b", "")
		if err != nil {
			return r.failure(roomUnavailable)
		}
		if len(page.events) == 0 || !r.match(page.events[0], local[n], p.EventID) {
			return r.failure(roomHeadMismatch)
		}
		return r.cover(ctx, b, local, receipts, page.start)
	})
	if err != nil {
		r.c.ready = false
	}
	return err
}
func (r *Reconciliation) policy(ctx context.Context, b *Budget, nonempty bool) error {
	err := r.c.CheckPolicy(ctx, b)
	if err == roomPolicyInvalid && nonempty {
		return r.fence(ctx, b, roomPolicyInvalid, "")
	}
	if err != nil {
		return r.failure(ReadinessCode(err.Error()))
	}
	return nil
}
func (r *Reconciliation) cover(ctx context.Context, b *Budget, local []*Delivery, receipts []Position, tail string) error {
	if err := r.policy(ctx, b, len(receipts) > 0); err != nil {
		return err
	}
	next := r.state
	next.Receipts = receipts
	if len(receipts) > 0 {
		next.HeadLine = append(append([]byte{}, local[len(receipts)-1].line...), '\n')
		for i := range next.Marks {
			mark, err := r.scan(ctx, b, i, local, receipts, tail)
			if err != nil {
				return err
			}
			next.Marks[i] = mark
		}
	}
	if err := r.policy(ctx, b, len(receipts) > 0); err != nil {
		return err
	}
	if err := r.save(ctx, b, next); err != nil {
		return err
	}
	r.c.ready = true
	r.diagnostic = ""
	return nil
}
func (r *Reconciliation) scan(ctx context.Context, b *Budget, index int, local []*Delivery, receipts []Position, tail string) (watermark, error) {
	filter := coverageFilters[index]
	mark := r.state.Marks[index]
	if mark.Event == nil {
		if len(r.state.Receipts) != 0 {
			return mark, r.failure(roomUnavailable)
		}
		first := receipts[0]
		anchor, _, _, end, err := r.c.contextAt(ctx, b, first.EventID, filter, "0")
		if err != nil || !r.match(anchor, local[0], first.EventID) {
			return mark, r.failure(roomUnavailable)
		}
		mark = watermark{anchor, end, end}
	}
	id, _ := mark.Event["event_id"].(string)
	anchor, _, _, end, err := r.c.contextAt(ctx, b, id, filter, "0")
	if err != nil || !r.sameEvent(anchor, mark.Event) || end != mark.AnchorToken {
		return mark, r.failure(roomUnavailable)
	}
	from := mark.Token
	seen := map[string]bool{from: true}
	last := mark.Event
	cursor := int64(0)
	if index == 0 {
		content, _ := mark.Event["content"].(map[string]any)
		raw, _ := json.Marshal(content["seq"])
		json.Unmarshal(raw, &cursor)
	}
	for {
		page, err := r.c.history(ctx, b, filter, "f", from, tail)
		if err != nil {
			return mark, r.failure(roomUnavailable)
		}
		for _, e := range page.events {
			id, ok := validEventID(e["event_id"])
			if !ok {
				if e["type"] == EventType {
					return mark, r.fence(ctx, b, roomHeadMismatch, eventIDString(e))
				}
				return mark, r.failure(roomUnavailable)
			}
			if e["type"] == EventType {
				content, _ := e["content"].(map[string]any)
				seq, ok := content["seq"].(int64)
				if !ok || seq < 1 || seq > int64(len(receipts)) || seq != cursor+1 || !r.match(e, local[seq-1], receipts[seq-1].EventID) {
					return mark, r.fence(ctx, b, roomHeadMismatch, id)
				}
				cursor = seq
			} else if index == 0 || !r.membership(e) {
				return mark, r.fence(ctx, b, roomPolicyInvalid, id)
			}
			last = e
		}
		if page.end == "" {
			break
		}
		if seen[page.end] {
			return mark, r.failure(roomUnavailable)
		}
		seen[page.end] = true
		from = page.end
	}
	if index == 0 && cursor != int64(len(receipts)) {
		return mark, r.failure(roomUnavailable)
	}
	id, _ = last["event_id"].(string)
	observed, _, _, end, err := r.c.contextAt(ctx, b, id, filter, "0")
	if err != nil || !r.sameEvent(observed, last) {
		return mark, r.failure(roomUnavailable)
	}
	return watermark{last, tail, end}, nil
}
func (r *Reconciliation) membership(e map[string]any) bool {
	sender, sOK := e["sender"].(string)
	user, uOK := e["state_key"].(string)
	content, cOK := e["content"].(map[string]any)
	unsigned, _ := e["unsigned"].(map[string]any)
	prev, _ := unsigned["prev_content"].(map[string]any)
	member, _ := content["membership"].(string)
	before, _ := prev["membership"].(string)
	_, server, _ := strings.Cut(r.c.cfg.User, ":")
	name, other, valid := strings.Cut(strings.TrimPrefix(user, "@"), ":")
	if !sOK || !uOK || !cOK || sender != user || !valid || name == "" || !strings.HasPrefix(user, "@") || other != server {
		return false
	}
	if _, present := unsigned["redacted_because"]; present {
		return false
	}
	if user == r.c.cfg.User {
		return member == "join" && before == "join"
	}
	return (member == "join" && (before == "join" || before == "invite")) || (member == "leave" && (before == "join" || before == "invite"))
}
func (r *Reconciliation) predecessor(ctx context.Context, b *Budget, p Position, local []*Delivery) error {
	anchor, events, from, _, err := r.c.contextAt(ctx, b, p.EventID, coverageFilters[0], "1024")
	if err != nil {
		return r.failure(roomUnavailable)
	}
	if !r.match(anchor, local[p.Sequence-1], p.EventID) {
		return r.failure(roomHeadMismatch)
	}
	seen := map[string]bool{from: true}
	done := false
	for {
		for _, e := range events {
			id := eventIDString(e)
			if e["type"] == EventType {
				if p.Sequence == 1 || !r.match(e, local[p.Sequence-2], r.state.Receipts[p.Sequence-2].EventID) {
					return r.fence(ctx, b, roomHeadMismatch, id)
				}
				return nil
			}
			if p.Sequence > 1 {
				return r.fence(ctx, b, roomPolicyInvalid, id)
			}
		}
		if done {
			if p.Sequence != 1 {
				return r.failure(roomHeadMismatch)
			}
			return nil
		}
		page, e := r.c.history(ctx, b, coverageFilters[0], "b", from)
		if e != nil {
			return r.failure(roomUnavailable)
		}
		events = page.events
		done = page.end == ""
		if !done {
			if seen[page.end] {
				return r.failure(roomUnavailable)
			}
			seen[page.end] = true
			from = page.end
		}
	}
}
func eventIDString(e map[string]any) string { id, _ := e["event_id"].(string); return id }

// Transport metadata such as unsigned.age is not part of anchor continuity.
func (r *Reconciliation) sameEvent(a, b map[string]any) bool {
	stable := func(e map[string]any) []byte {
		out := map[string]any{"room_id": r.c.cfg.Room}
		for _, key := range []string{"event_id", "room_id", "type", "sender", "state_key", "content", "redacts", "redacted_because"} {
			if v, ok := e[key]; ok {
				out[key] = v
			}
		}
		if unsigned, ok := e["unsigned"].(map[string]any); ok {
			for _, key := range []string{"prev_content", "redacted_because"} {
				if v, ok := unsigned[key]; ok {
					out["unsigned."+key] = v
				}
			}
		}
		raw, _ := json.Marshal(out)
		return raw
	}
	return a != nil && b != nil && string(stable(a)) == string(stable(b))
}
