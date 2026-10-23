package adapters

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/ccj"
)

func auditLine(t *testing.T, seq int64, prev string) []byte {
	t.Helper()
	obj := map[string]any{"v": int64(1), "seq": seq, "at": "2030-01-01T00:00:00Z", "instance": "AQAAAAAAAAAAAAAAAAAAAA", "jti": nil, "key_id": nil, "host": nil, "name": nil, "outcome": "refused", "code": "registration_malformed", "http_status": int64(400), "registry_revision": nil, "jwt_iat": nil, "jwt_exp": nil, "request_bytes": int64(0), "prev_hash": prev}
	raw, err := ccj.Marshal(obj, auditUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
func editAudit(t *testing.T, line []byte, edit func(map[string]any)) []byte {
	t.Helper()
	v, err := ccj.Parse(line[:len(line)-1], auditUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(map[string]any)
	edit(obj)
	raw, err := ccj.Marshal(obj, auditUnavailable)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}
func auditFixture(t *testing.T, remote Remote) (*Audit, string) {
	t.Helper()
	path := filepath.Join(tempDir(t), "audit")
	a, err := NewAudit(context.Background(), path, remote)
	if err != nil {
		t.Fatal("audit fixture")
	}
	t.Cleanup(func() { a.Close() })
	return a, path
}

type remoteFixture struct {
	bad, fail bool
	lines     [][]byte
	entered   chan struct{}
}

func (r *remoteFixture) Commit(ctx context.Context, line []byte) ([32]byte, error) {
	if r.entered != nil {
		r.entered <- struct{}{}
		<-ctx.Done()
		return [32]byte{}, ctx.Err()
	}
	if r.fail {
		return [32]byte{}, errors.New("synthetic remote failure")
	}
	r.lines = append(r.lines, bytes.Clone(line))
	if r.bad {
		return [32]byte{}, nil
	}
	return sha256.Sum256(line), nil
}

// Local fsync does not substitute for authenticated off-host acknowledgement:
// an absent remote refuses issuance acknowledgement while exact durable local
// bytes remain available. An explicit test remote supplies the positive control.
func TestAuditNoRemote(t *testing.T) {
	a, path := auditFixture(t, nil)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.Acknowledge(context.Background(), line), auditUnavailable)
	raw, err := os.ReadFile(path)
	sum := sha256.Sum256(line)
	if err != nil || !bytes.Equal(raw, line) || a.Head() != (Head{1, hex.EncodeToString(sum[:])}) {
		t.Fatal("local bytes/head")
	}
	remote := &remoteFixture{}
	b, _ := auditFixture(t, remote)
	if err = b.Append(context.Background(), line); err != nil {
		t.Fatal(err)
	}
	if err = b.Acknowledge(context.Background(), line); err != nil || len(remote.lines) != 1 || !bytes.Equal(remote.lines[0], line) {
		t.Fatal("exact ack control")
	}
}

// The sink rejects wrong sequence/hash/schema/canonical framing before writing
// any bytes. Each rejection has a nearby unchanged canonical line that succeeds.
func TestAuditIntegrity(t *testing.T) {
	for _, kind := range []string{"seq", "hash", "extra", "code", "status", "jwt", "canonical", "partial", "extra LF"} {
		t.Run(kind, func(t *testing.T) {
			a, path := auditFixture(t, nil)
			good := auditLine(t, 1, strings.Repeat("0", 64))
			bad := bytes.Clone(good)
			switch kind {
			case "seq":
				bad = editAudit(t, good, func(m map[string]any) { m["seq"] = int64(2) })
			case "hash":
				bad = editAudit(t, good, func(m map[string]any) { m["prev_hash"] = strings.Repeat("1", 64) })
			case "extra":
				bad = editAudit(t, good, func(m map[string]any) { m["jwt"] = "public forbidden fixture" })
			case "code":
				bad = editAudit(t, good, func(m map[string]any) { m["code"] = "arbitrary exception" })
			case "status":
				bad = editAudit(t, good, func(m map[string]any) { m["code"] = "audience_mismatch"; m["http_status"] = int64(400) })
			case "jwt":
				bad = editAudit(t, good, func(m map[string]any) { m["jwt_iat"] = int64(1) })
			case "canonical":
				bad = append([]byte(" "), good...)
			case "partial":
				bad = bad[:len(bad)-1]
			case "extra LF":
				bad = append(bad, '\n')
			}
			wantCode(t, a.Append(context.Background(), bad), auditUnavailable)
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) != 0 || a.Head().Sequence != 0 {
				t.Fatal("partial invalid write")
			}
			if err = a.Append(context.Background(), good); err != nil {
				t.Fatal("canonical control")
			}
		})
	}
}

// An issued line with a wrong lifetime is refused without bytes or head advance;
// its valid 120-second counterpart is recorded and acknowledged byte-for-byte.
// This checks audit metadata, not the validity or delivery of an actual JWT.
func TestAuditIssued(t *testing.T) {
	remote := &remoteFixture{}
	a, path := auditFixture(t, remote)
	good := editAudit(t, auditLine(t, 1, strings.Repeat("0", 64)), func(m map[string]any) {
		m["outcome"], m["code"], m["http_status"] = "issued", "issued", int64(200)
		m["jwt_iat"], m["jwt_exp"] = int64(1), int64(121)
		m["jti"], m["key_id"] = "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
		m["host"], m["name"], m["registry_revision"] = "host-a", "host-a_project_role", strings.Repeat("3", 40)
	})
	bad := editAudit(t, good, func(m map[string]any) { m["jwt_exp"] = int64(122) })
	wantCode(t, a.Append(context.Background(), bad), auditUnavailable)
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 0 || a.Head() != firstHead() {
		t.Fatal("invalid issuance changed audit")
	}
	if err = a.Append(context.Background(), good); err != nil {
		t.Fatal("issued control")
	}
	if err = a.Acknowledge(context.Background(), good); err != nil {
		t.Fatal("issued exact acknowledgement")
	}
	raw, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, good) || len(remote.lines) != 1 || !bytes.Equal(remote.lines[0], good) {
		t.Fatal("issued bytes changed")
	}
}

// Retained logs are validated on startup; torn lines are never truncated or
// silently repaired. A complete valid log reopens with the independent LF hash.
func TestAuditCorruptStartupAndProbe(t *testing.T) {
	path := filepath.Join(tempDir(t), "audit")
	line := auditLine(t, 1, strings.Repeat("0", 64))
	write(t, path, line[:len(line)-1], 0600)
	_, err := NewAudit(context.Background(), path, nil)
	wantCode(t, err, auditUnavailable)
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, line[:len(line)-1]) {
		t.Fatal("torn record rewritten")
	}
	write(t, path, line, 0600)
	a, err := NewAudit(context.Background(), path, nil)
	if err != nil {
		t.Fatal("valid retained control")
	}
	defer a.Close()
	wantCode(t, a.Probe(context.Background(), firstHead()), auditUnavailable)
	if err = a.Probe(context.Background(), a.Head()); err != nil {
		t.Fatal("exact tip control")
	}
	_, err = NewAudit(context.Background(), path, nil)
	wantCode(t, err, auditUnavailable)
}

// Recovery cannot adopt a different cached head, even when an external writer
// replaces the file contents with a valid earlier prefix. Restoring the exact
// retained head permits a probe and does not rewrite or truncate any bytes.
func TestAuditProbeNoRollback(t *testing.T) {
	a, path := auditFixture(t, nil)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal("append control")
	}
	head := a.Head()
	write(t, path, nil, 0600)
	wantCode(t, a.Probe(context.Background(), firstHead()), auditUnavailable)
	if a.Head() != head {
		t.Fatal("probe rolled back cached head")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 0 {
		t.Fatal("probe rewrote bytes")
	}
	write(t, path, line, 0600)
	if err = a.Probe(context.Background(), head); err != nil {
		t.Fatal("exact restored control")
	}
}

// Acknowledgement must match exact line bytes, ships local prerequisites in
// order, and safely deduplicates an older concurrent acknowledgement request.
func TestAuditRemoteExactAndSpool(t *testing.T) {
	remote := &remoteFixture{bad: true}
	a, _ := auditFixture(t, remote)
	first := auditLine(t, 1, strings.Repeat("0", 64))
	sum := sha256.Sum256(first)
	second := auditLine(t, 2, hex.EncodeToString(sum[:]))
	if err := a.Append(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := a.Append(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	wantCode(t, a.Acknowledge(context.Background(), second), auditUnavailable)
	remote.bad = false
	if err := a.Acknowledge(context.Background(), second); err != nil {
		t.Fatal("exact remote control")
	}
	if len(remote.lines) != 3 || !bytes.Equal(remote.lines[1], first) || !bytes.Equal(remote.lines[2], second) {
		t.Fatal("spool order/bytes")
	}
	if err := a.Acknowledge(context.Background(), first); err != nil || len(remote.lines) != 3 {
		t.Fatal("older acknowledgement duplicated")
	}
	changed := editAudit(t, second, func(m map[string]any) { m["request_bytes"] = int64(1) })
	wantCode(t, a.Acknowledge(context.Background(), changed), auditUnavailable)
}

// Cancellation prevents acknowledgement success and never changes durable
// records; the remote fixture blocks only until its caller context is cancelled.
func TestAuditCancellation(t *testing.T) {
	remote := &remoteFixture{entered: make(chan struct{}, 1)}
	a, path := auditFixture(t, remote)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- a.Acknowledge(ctx, line) }()
	<-remote.entered
	cancel()
	wantCode(t, <-result, auditUnavailable)
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, line) {
		t.Fatal("cancel altered durable bytes")
	}
	remote.entered = nil
	if err := a.Acknowledge(context.Background(), line); err != nil {
		t.Fatal("uncancelled control")
	}
}

// File permissions, name replacement and closed descriptors fail recording;
// no unsafe file is silently repaired. Restoring permissions permits a valid
// append before any byte was written, and symlink construction always refuses.
func TestAuditFilesystemFailures(t *testing.T) {
	a, path := auditFixture(t, nil)
	line := auditLine(t, 1, strings.Repeat("0", 64))
	os.Chmod(path, 0644)
	wantCode(t, a.Append(context.Background(), line), auditUnavailable)
	os.Chmod(path, 0600)
	if err := a.Append(context.Background(), line); err != nil {
		t.Fatal("protected control")
	}
	replacement := filepath.Join(filepath.Dir(path), "replaced")
	os.Rename(path, replacement)
	wantCode(t, a.Probe(context.Background(), a.Head()), auditUnavailable)
	link := filepath.Join(tempDir(t), "link")
	os.Symlink(replacement, link)
	_, err := NewAudit(context.Background(), link, nil)
	wantCode(t, err, auditUnavailable)
	a.file.Close()
	wantCode(t, a.Probe(context.Background(), a.Head()), auditUnavailable)
}
