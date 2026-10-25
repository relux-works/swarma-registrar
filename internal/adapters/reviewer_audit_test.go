package adapters

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
)

// Exact remote bytes cannot repair loss/replacement of the locally durable
// pathname. Acknowledge must refuse after that loss, even while its old fd reads.
// A fresh unchanged local sink is the nearby positive control.
func TestReviewAuditDetachedAck(t *testing.T) {
	for _, kind := range []string{"unlinked", "replaced", "unsafe-mode"} {
		t.Run(kind, func(t *testing.T) {
			remote := &remoteFixture{}
			a, path := auditFixture(t, remote)
			line := auditLine(t, 1, strings.Repeat("0", 64))
			if err := a.Append(context.Background(), line); err != nil {
				t.Fatal("durable append control")
			}
			switch kind {
			case "unlinked":
				if err := os.Remove(path); err != nil {
					t.Fatal("fixture unlink")
				}
			case "replaced":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal("fixture rename")
				}
				write(t, path, nil, 0600)
			case "unsafe-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal("fixture permission change")
				}
			}
			err := a.Acknowledge(context.Background(), line)
			if err == nil {
				t.Errorf("unusable local file still acknowledged: kind=%s remote_lines=%d", kind, len(remote.lines))
			} else {
				wantCode(t, err, auditUnavailable)
			}
			wantCode(t, a.Probe(context.Background(), a.Head()), auditUnavailable)
			goodRemote := &remoteFixture{}
			good, _ := auditFixture(t, goodRemote)
			if err = good.Append(context.Background(), line); err != nil {
				t.Fatal("valid append")
			}
			if err = good.Acknowledge(context.Background(), line); err != nil {
				t.Fatal("intact ack control")
			}
		})
	}
}

// A corrupt unacknowledged prerequisite or a different requested line must
// never be shipped as the claimed exact chain; restart replays intact records.
func TestReviewAuditReplay(t *testing.T) {
	remote := &remoteFixture{}
	a, path := auditFixture(t, remote)
	one := auditLine(t, 1, strings.Repeat("0", 64))
	two := auditLine(t, 2, lineHash(one))
	if err := a.Append(context.Background(), one); err != nil {
		t.Fatal(err)
	}
	if err := a.Append(context.Background(), two); err != nil {
		t.Fatal(err)
	}
	changed := editAudit(t, one, func(m map[string]any) { m["request_bytes"] = int64(1) })
	write(t, path, append(bytes.Clone(changed), two...), 0600)
	wantCode(t, a.Acknowledge(context.Background(), two), auditUnavailable)
	if len(remote.lines) > 1 {
		t.Fatal("broken second link shipped")
	}
	write(t, path, append(bytes.Clone(one), two...), 0600)
	if err := a.Probe(context.Background(), a.Head()); err != nil {
		t.Fatal("restored head control")
	}
	if err := a.Close(); err != nil {
		t.Fatal("close fixture")
	}
	freshRemote := &remoteFixture{}
	fresh, err := NewAudit(context.Background(), path, freshRemote, "sha1")
	if err != nil {
		t.Fatal("valid restart")
	}
	defer fresh.Close()
	if err = fresh.Acknowledge(context.Background(), two); err != nil || len(freshRemote.lines) != 2 || !bytes.Equal(freshRemote.lines[0], one) || !bytes.Equal(freshRemote.lines[1], two) {
		t.Fatal("restart replay order")
	}
}

type reviewRemote struct {
	remove  string
	corrupt bool
	calls   int
}

func (r *reviewRemote) Commit(ctx context.Context, line []byte) ([32]byte, error) {
	r.calls++
	sum := sha256.Sum256(line)
	if r.remove != "" {
		if err := os.Remove(r.remove); err != nil {
			return [32]byte{}, err
		}
		r.remove = ""
	}
	if r.corrupt {
		sum[31] ^= 1
	}
	return sum, nil
}

// Local durability must still exist when remote acknowledgement completes.
// Removal is an isolated fault injected during the otherwise exact remote ack.
func TestReviewAuditLossDuringAck(t *testing.T) {
	remote := &reviewRemote{}
	a, path := auditFixture(t, remote)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal("durable append")
	}
	remote.remove = path
	err := a.Acknowledge(context.Background(), line)
	if err == nil {
		t.Fatal("acknowledgement succeeded after local file disappeared during remote commit")
	}
	wantCode(t, err, auditUnavailable)
}

// Matching a digest prefix is not exact-byte acknowledgement. A wrong last byte
// must refuse without advancing the acknowledged head; a full match then works.
func TestReviewAuditAckPrefix(t *testing.T) {
	remote := &reviewRemote{corrupt: true}
	a, _ := auditFixture(t, remote)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal(err)
	}
	err := a.Acknowledge(context.Background(), line)
	if err == nil {
		t.Fatal("digest-prefix acknowledgement accepted")
	}
	wantCode(t, err, auditUnavailable)
	if a.acked != firstHead() {
		t.Fatal("wrong acknowledgement advanced cursor")
	}
	remote.corrupt = false
	if err = a.Acknowledge(context.Background(), line); err != nil {
		t.Fatal("full digest control")
	}
}
