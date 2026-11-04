package matrixaudit

import (
	"context"
	"net/url"
)

// ReconcileHead compares a fresh audit-only remote head to the caller's validated
// local bytes and retained receipt. A nil receipt with nil bytes denotes empty.
// Call under the delivery lock, at startup and before each candidate append.
// This observation never substitutes for prefix verification or durable coverage.
func (c *Client) ReconcileHead(ctx context.Context, b *Budget, want *Position, line []byte) error {
	var d *Delivery
	if want != nil {
		var err error
		d, err = c.delivery(line)
		_, valid := validEventID(want.EventID)
		if err != nil || !valid || want.RoomID != c.cfg.Room || want.Sequence != d.seq || want.SHA256 != d.hash {
			return roomHeadMismatch
		}
	} else if len(line) != 0 {
		return roomHeadMismatch
	}
	from := ""
	seen := map[string]bool{}
	for {
		query := url.Values{"dir": {"b"}, "limit": {"1024"}, "filter": {`{"types":["works.relux.registrar.audit.v0"]}`}}
		if from != "" {
			query.Set("from", from)
		}
		value, err := c.requestJSON(ctx, b, "GET", []string{"rooms", c.cfg.Room, "messages"}, query, nil, pageBytes)
		if err != nil {
			return roomUnavailable
		}
		page, ok := value.(map[string]any)
		if !ok {
			return roomUnavailable
		}
		start, ok := page["start"].(string)
		if !ok || start == "" || (from != "" && start != from) {
			return roomUnavailable
		}
		chunk, ok := page["chunk"].([]any)
		if !ok || len(chunk) > pageEvents {
			return roomUnavailable
		}
		// Validate the entire returned timeline, even beyond its newest event.
		for _, value := range chunk {
			e, ok := value.(map[string]any)
			if !ok || e["type"] != EventType {
				return roomUnavailable
			}
		}
		if len(chunk) > 0 {
			e := chunk[0].(map[string]any)
			if want == nil {
				return roomHeadMismatch
			}
			// Room-scoped timeline responses may omit room_id; a conflicting one fails.
			if _, present := e["room_id"]; !present {
				e["room_id"] = c.cfg.Room
			}
			if !d.matches(e, want.EventID) {
				return roomHeadMismatch
			}
			if b.check(ctx) != nil {
				return roomUnavailable
			}
			return nil
		}
		end, present := page["end"]
		if !present {
			if b.check(ctx) != nil {
				return roomUnavailable
			}
			return emptyHead(want)
		}
		token, ok := end.(string)
		if !ok || token == "" || token == start || seen[token] {
			return roomUnavailable
		}
		seen[start] = true
		seen[token] = true
		from = token
	}
}
func emptyHead(want *Position) error {
	if want != nil {
		return roomHeadMismatch
	}
	return nil
}
