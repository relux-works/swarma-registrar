package matrixaudit

import (
	"context"
	"strings"
)

// ReadinessCode is a static diagnostic, separate from admission HTTP refusals.
type ReadinessCode string

func (code ReadinessCode) Error() string { return string(code) }

const (
	RoomUnavailable   ReadinessCode = "audit_room_unavailable"
	RoomPolicyInvalid ReadinessCode = "audit_room_policy_invalid"
	RoomHeadMismatch  ReadinessCode = "audit_room_head_mismatch"
)

const pageBytes = 4 * 1024 * 1024
const pageEvents = 1024

// CheckPolicy observes the complete current state within the caller's original
// budget. The caller owns serialization, persistent fences and admission readiness;
// success alone never authorizes replay, acknowledgement or JWT release.
func (c *Client) CheckPolicy(ctx context.Context, b *Budget) error {
	value, err := c.requestJSON(ctx, b, "GET", []string{"rooms", c.cfg.Room, "state"}, nil, nil, pageBytes)
	if err != nil {
		return roomUnavailable
	}
	events, ok := value.([]any)
	if !ok || len(events) > pageEvents {
		return roomUnavailable
	}
	state := map[string]map[string]map[string]any{}
	for _, value := range events {
		e, ok := value.(map[string]any)
		if !ok {
			return roomUnavailable
		}
		typ, typeOK := e["type"].(string)
		key, keyOK := e["state_key"].(string)
		sender, senderOK := e["sender"].(string)
		content, contentOK := e["content"].(map[string]any)
		if !typeOK || typ == "" || !keyOK || !senderOK || sender == "" || !contentOK {
			return roomUnavailable
		}
		if state[typ] == nil {
			state[typ] = map[string]map[string]any{}
		}
		if _, duplicate := state[typ][key]; duplicate {
			return roomUnavailable
		}
		state[typ][key] = content
		if typ == "m.room.create" && (key != "" || sender != c.cfg.User) {
			return roomPolicyInvalid
		}
	}
	create := state["m.room.create"][""]
	if create == nil || create["room_version"] != "11" || create["m.federate"] != false {
		return roomPolicyInvalid
	}
	if _, present := create["predecessor"]; present {
		return roomPolicyInvalid
	}
	if len(state["m.room.encryption"]) != 0 || len(state["m.room.tombstone"]) != 0 {
		return roomPolicyInvalid
	}
	for typ, field := range map[string]string{"m.room.join_rules": "join_rule", "m.room.history_visibility": "history_visibility", "m.room.guest_access": "guest_access"} {
		want := map[string]string{"join_rule": "invite", "history_visibility": "shared", "guest_access": "forbidden"}[field]
		if state[typ][""][field] != want {
			return roomPolicyInvalid
		}
	}
	_, server, valid := strings.Cut(c.cfg.User, ":")
	if !valid {
		return roomPolicyInvalid
	}
	for user, member := range state["m.room.member"] {
		membership, ok := member["membership"].(string)
		if !ok || (membership != "join" && membership != "invite" && membership != "leave" && membership != "ban" && membership != "knock") {
			return roomPolicyInvalid
		}
		if membership == "join" || membership == "invite" {
			local, memberServer, ok := strings.Cut(strings.TrimPrefix(user, "@"), ":")
			if !ok || local == "" || !strings.HasPrefix(user, "@") || memberServer != server {
				return roomPolicyInvalid
			}
		}
	}
	if state["m.room.member"][c.cfg.User]["membership"] != "join" {
		return roomPolicyInvalid
	}
	p := state["m.room.power_levels"][""]
	for field, want := range map[string]int64{"users_default": 0, "events_default": 101, "state_default": 101, "invite": 101, "kick": 101, "ban": 101, "redact": 101} {
		if p[field] != want {
			return roomPolicyInvalid
		}
	}
	users, ok := p["users"].(map[string]any)
	if !ok || users[c.cfg.User] != int64(100) {
		return roomPolicyInvalid
	}
	for user, level := range users {
		want := int64(0)
		if user == c.cfg.User {
			want = 100
		}
		if level != want {
			return roomPolicyInvalid
		}
	}
	overrides, ok := p["events"].(map[string]any)
	if !ok || len(overrides) != 1 || overrides[EventType] != int64(100) {
		return roomPolicyInvalid
	}
	if b.check(ctx) != nil {
		return roomUnavailable
	}
	return nil
}
