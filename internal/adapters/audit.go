package adapters

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/envelope"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
)

var auditID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var auditHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

const maxAuditLine = 16384

func lineHash(line []byte) string { sum := sha256.Sum256(line); return hex.EncodeToString(sum[:]) }
func firstHead() Head             { return Head{Hash: strings.Repeat("0", 64)} }

type Head struct {
	Sequence int64
	Hash     string
}

// Remote must be authenticated, append-only and durable, and idempotent for the
// same exact chained line. Its result is SHA-256 of the committed bytes including
// LF, never merely an HTTP success. It must honor cancellation. No production
// implementation or network transport is supplied.
type Remote interface {
	Commit(context.Context, []byte) ([32]byte, error)
}

// Audit holds one exclusive local writer and validates the complete retained
// chain. Local recording is usable without Remote; Acknowledge then fails closed.
type Audit struct {
	mu          sync.Mutex
	file        *os.File
	path        string
	head        Head
	size        int64
	bad, closed bool
	remote      Remote
	remoteGate  chan struct{}
	acked       Head
	ackOffset   int64
}

func NewAudit(parent context.Context, path string, remote Remote) (*Audit, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if !absolute(path) || !privateDirectory(filepath.Dir(path)) {
		return nil, failure(auditUnavailable)
	}
	f, err := nofollow(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT, 0600)
	if err != nil {
		return nil, failure(auditUnavailable)
	}
	fail := func() (*Audit, error) { f.Close(); return nil, failure(auditUnavailable) }
	info, err := f.Stat()
	if err != nil || !privateFile(info) {
		return fail()
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail()
	}
	a := &Audit{file: f, path: path, head: firstHead(), remote: remote, remoteGate: make(chan struct{}, 1), acked: firstHead()}
	a.remoteGate <- struct{}{}
	head, size, err := a.scan(ctx)
	if err != nil {
		return fail()
	}
	a.head = head
	a.size = size
	if err = f.Sync(); err != nil {
		return fail()
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fail()
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return fail()
	}
	return a, nil
}
func (a *Audit) Head() Head { a.mu.Lock(); defer a.mu.Unlock(); return a.head }
func inspectLine(line []byte) (map[string]any, error) {
	bad := func() (map[string]any, error) { return nil, failure(auditUnavailable) }
	if len(line) > maxAuditLine || len(line) < 2 || line[len(line)-1] != '\n' {
		return bad()
	}
	value, err := ccj.Parse(line[:len(line)-1], auditUnavailable)
	if err != nil {
		return bad()
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != 16 {
		return bad()
	}
	for _, key := range strings.Fields("v seq at instance jti key_id host name outcome code http_status registry_revision jwt_iat jwt_exp request_bytes prev_hash") {
		if _, ok := obj[key]; !ok {
			return bad()
		}
	}
	canonical, err := ccj.Marshal(value, auditUnavailable)
	if err != nil || !bytes.Equal(append(canonical, '\n'), line) {
		return bad()
	}
	seq, ok := obj["seq"].(int64)
	if !ok || seq < 1 || obj["v"] != int64(1) {
		return bad()
	}
	at, ok := obj["at"].(string)
	if !ok {
		return bad()
	}
	if _, ok = registration.ParseTimestamp(at); !ok {
		return bad()
	}
	instance, ok := obj["instance"].(string)
	if !ok {
		return bad()
	}
	nonce, ok := envelope.DecodeBase64URL(instance)
	if !ok || len(nonce) != 16 {
		return bad()
	}
	for _, key := range []string{"jti", "key_id"} {
		if obj[key] != nil {
			s, ok := obj[key].(string)
			if !ok || !auditID.MatchString(s) {
				return bad()
			}
		}
	}
	if obj["host"] != nil {
		s, ok := obj["host"].(string)
		if !ok || !enrollment.ValidHost(s) {
			return bad()
		}
	}
	if obj["name"] != nil {
		s, ok := obj["name"].(string)
		if !ok || (&registration.Body{Name: s}).CheckName("") != nil {
			return bad()
		}
	}
	if obj["registry_revision"] != nil {
		s, ok := obj["registry_revision"].(string)
		if !ok || !fullRevision(s) {
			return bad()
		}
	}
	previous, ok := obj["prev_hash"].(string)
	if !ok || !auditHash.MatchString(previous) {
		return bad()
	}
	count, ok := obj["request_bytes"].(int64)
	if !ok || count < 0 || count > 65537 {
		return bad()
	}
	outcome, ok := obj["outcome"].(string)
	if !ok {
		return bad()
	}
	code, ok := obj["code"].(string)
	if !ok {
		return bad()
	}
	if outcome == "issued" {
		iat, ok := obj["jwt_iat"].(int64)
		if !ok || iat < 0 || obj["jwt_exp"] != iat+120 || code != "issued" || obj["http_status"] != int64(200) {
			return bad()
		}
	} else if outcome == "refused" {
		status := auditStatus(refusal.Code(code))
		if status == 0 || obj["http_status"] != status || obj["jwt_iat"] != nil || obj["jwt_exp"] != nil {
			return bad()
		}
	} else {
		return bad()
	}
	return obj, nil
}
func auditStatus(code refusal.Code) int64 {
	switch code {
	case "endpoint_not_found":
		return 404
	case "method_not_allowed":
		return 405
	case "request_too_large":
		return 413
	case "unsupported_media_type":
		return 415
	case "registration_malformed", "registration_id_mismatch", "name_invalid", "clock_skew":
		return 400
	case "registration_signature_invalid", "signature_high_s", "key_not_enrolled", "key_not_valid_now", "host_revoked", "name_not_permitted", "audience_mismatch", "request_not_yet_valid", "request_expired":
		return 403
	case "nonce_replayed":
		return 409
	case "rate_limited":
		return 429
	case "registry_unavailable", "service_unavailable", "audit_unavailable":
		return 503
	}
	return 0
}
func (a *Audit) identity() (int64, error) {
	info, err := a.file.Stat()
	if err != nil || !privateFile(info) {
		return 0, failure(auditUnavailable)
	}
	named, err := os.Lstat(a.path)
	if err != nil || !os.SameFile(info, named) {
		return 0, failure(auditUnavailable)
	}
	return info.Size(), nil
}
func (a *Audit) lineAt(offset, end int64) ([]byte, error) {
	if offset >= end {
		return nil, io.EOF
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(a.file, offset, end-offset), maxAuditLine)
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return nil, failure(auditUnavailable)
	}
	return bytes.Clone(line), nil
}
func (a *Audit) scan(ctx context.Context) (Head, int64, error) {
	end, err := a.identity()
	if err != nil {
		return Head{}, 0, err
	}
	head := firstHead()
	offset := int64(0)
	for offset < end {
		if ctx.Err() != nil {
			return Head{}, 0, failure(auditUnavailable)
		}
		line, err := a.lineAt(offset, end)
		if err != nil {
			return Head{}, 0, err
		}
		obj, err := inspectLine(line)
		if err != nil || obj["seq"] != head.Sequence+1 || obj["prev_hash"] != head.Hash {
			return Head{}, 0, failure(auditUnavailable)
		}
		offset += int64(len(line))
		head = Head{obj["seq"].(int64), lineHash(line)}
	}
	return head, offset, nil
}
func (a *Audit) Append(ctx context.Context, line []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.bad || ctx.Err() != nil {
		return failure(auditUnavailable)
	}
	obj, err := inspectLine(line)
	if err != nil || obj["seq"] != a.head.Sequence+1 || obj["prev_hash"] != a.head.Hash {
		return failure(auditUnavailable)
	}
	size, err := a.identity()
	if err != nil || size != a.size {
		return failure(auditUnavailable)
	}
	a.bad = true // Any partial write, fsync error or interruption requires exact-head recovery.
	if n, err := a.file.Write(line); err != nil || n != len(line) {
		return failure(auditUnavailable)
	}
	if err = a.file.Sync(); err != nil || ctx.Err() != nil {
		return failure(auditUnavailable)
	}
	a.head = Head{obj["seq"].(int64), lineHash(line)}
	a.size += int64(len(line))
	a.bad = false
	return nil
}
func (a *Audit) Acknowledge(ctx context.Context, line []byte) error {
	if a.remote == nil || ctx.Err() != nil {
		return failure(auditUnavailable)
	}
	select {
	case <-ctx.Done():
		return failure(auditUnavailable)
	case <-a.remoteGate:
	}
	defer func() { a.remoteGate <- struct{}{} }()
	target, err := inspectLine(line)
	if err != nil {
		return err
	}
	seq := target["seq"].(int64)
	a.mu.Lock()
	end := a.size
	unusable := a.closed || a.bad
	a.mu.Unlock()
	if unusable {
		return failure(auditUnavailable)
	}
	cursor := a.acked
	offset := a.ackOffset
	already := seq <= cursor.Sequence
	if already {
		cursor = firstHead()
		offset = 0
	}
	for cursor.Sequence < seq {
		if ctx.Err() != nil {
			return failure(auditUnavailable)
		}
		local, err := a.lineAt(offset, end)
		if err != nil {
			return failure(auditUnavailable)
		}
		obj, err := inspectLine(local)
		if err != nil || obj["seq"] != cursor.Sequence+1 || obj["prev_hash"] != cursor.Hash {
			return failure(auditUnavailable)
		}
		if obj["seq"] == seq && !bytes.Equal(local, line) {
			return failure(auditUnavailable)
		}
		if !already {
			ack, err := a.remote.Commit(ctx, bytes.Clone(local))
			if err != nil || ack != sha256.Sum256(local) {
				return failure(auditUnavailable)
			}
		}
		offset += int64(len(local))
		cursor = Head{obj["seq"].(int64), lineHash(local)}
		if !already {
			a.acked = cursor
			a.ackOffset = offset
		}
	}
	if ctx.Err() != nil {
		return failure(auditUnavailable)
	}
	return nil
}
func (a *Audit) Probe(ctx context.Context, expected Head) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || ctx.Err() != nil || expected != a.head {
		return failure(auditUnavailable)
	}
	actual, size, err := a.scan(ctx)
	if err != nil || actual != expected {
		return failure(auditUnavailable)
	}
	if err = a.file.Sync(); err != nil || ctx.Err() != nil {
		return failure(auditUnavailable)
	}
	a.head = actual
	a.size = size
	a.bad = false
	return nil
}
func (a *Audit) Close() error {
	<-a.remoteGate
	defer func() { a.remoteGate <- struct{}{} }()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if err := a.file.Close(); err != nil {
		return failure(auditUnavailable)
	}
	return nil
}
