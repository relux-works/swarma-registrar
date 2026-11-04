package matrixaudit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-registrar/ccj"
)

type watermark struct {
	Event       map[string]any
	Token       string
	AnchorToken string
}
type coverageState struct {
	Receipts []Position
	HeadLine []byte
	Marks    [2]watermark
	Fence    ReadinessCode
	Offender string
}
type journalRecord struct {
	Checkpoint checkpoint
	SHA256     string
}
type checkpoint struct {
	Binding, Previous string
	State             coverageState
}

// Reconciliation owns append-only coverage and incident evidence beside the
// exclusively locked binding. Serialize all methods with delivery and Close.
// The caller must additionally validate the complete local audit schema/custody.
type Reconciliation struct {
	c               *Client
	file            *os.File
	state           coverageState
	binding, digest string
	size            int64
	bad             bool
	diagnostic      ReadinessCode
}

func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// OpenReconciliation never replaces missing coverage for retained local history.
// Initialize before the first local append, under the original startup budget.
func (c *Client) OpenReconciliation(ctx context.Context, b *Budget, local [][]byte) (*Reconciliation, error) {
	if c.binding == nil || b.check(ctx) != nil {
		return nil, roomUnavailable
	}
	raw, err := io.ReadAll(io.NewSectionReader(c.binding, 0, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, roomUnavailable
	}
	r := &Reconciliation{c: c, binding: digest(raw)}
	path := c.cfg.BindingPath + ".coverage"
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	fresh := false
	if err == syscall.ENOENT {
		if !c.binding.fresh || len(local) != 0 || c.ReconcileHead(ctx, b, nil, nil) != nil {
			c.ready = false
			return nil, roomUnavailable
		}
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		fresh = true
		c.binding.fresh = false
	}
	if err != nil {
		c.ready = false
		return nil, roomUnavailable
	}
	r.file = os.NewFile(uintptr(fd), path)
	fail := func() (*Reconciliation, error) { r.file.Close(); c.ready = false; return nil, roomUnavailable }
	info, err := r.file.Stat()
	if err != nil || !private(info, 0600) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	if fresh {
		if r.save(ctx, b, r.state) != nil {
			return fail()
		}
		dir, e := os.Open(filepath.Dir(path))
		if e != nil {
			return fail()
		}
		e = dir.Sync()
		closeErr := dir.Close()
		if e != nil || closeErr != nil {
			return fail()
		}
	} else {
		scanner := bufio.NewScanner(r.file)
		scanner.Buffer(make([]byte, 4096), 16*1024*1024)
		for scanner.Scan() {
			if b.check(ctx) != nil {
				return fail()
			}
			line := bytes.Clone(scanner.Bytes())
			if _, e := ccj.Parse(line, "audit_room_unavailable"); e != nil {
				return fail()
			}
			var envelope journalRecord
			if json.Unmarshal(line, &envelope) != nil {
				return fail()
			}
			record := envelope.Checkpoint
			encoded, e := json.Marshal(record)
			if e != nil || digest(encoded) != envelope.SHA256 || record.Binding != r.binding || record.Previous != r.digest {
				return fail()
			}
			if r.state.Fence != "" && (record.State.Fence != r.state.Fence || record.State.Offender != r.state.Offender) {
				return fail()
			}
			// Each checkpoint carries only newly reconstructed receipts.
			// Prior receipts are immutable under the checksum chain.
			for i, p := range record.State.Receipts {
				if p.Sequence != int64(len(r.state.Receipts)+i+1) {
					return fail()
				}
			}
			record.State.Receipts = append(r.state.Receipts, record.State.Receipts...)

			r.state = record.State
			r.digest = digest(line)
			r.size += int64(len(line) + 1)
		}
		if scanner.Err() != nil || r.digest == "" || r.size != info.Size() {
			return fail()
		}
	}
	if b.check(ctx) != nil {
		return fail()
	}
	if r.state.Fence != "" {
		c.ready = false
	}
	return r, nil
}

// Close releases only this journal. Closing it also closes delivery readiness.
func (r *Reconciliation) Close() error {
	r.c.ready = false
	if r.file.Close() != nil {
		return roomUnavailable
	}
	return nil
}

// Receipt returns a copy of the durably reconstructed remote prefix head.
func (r *Reconciliation) Receipt() (Position, []byte) {
	if len(r.state.Receipts) == 0 {
		return Position{}, nil
	}
	return r.state.Receipts[len(r.state.Receipts)-1], bytes.Clone(r.state.HeadLine)
}
func (r *Reconciliation) failure(code ReadinessCode) error {
	r.diagnostic = code
	r.c.ready = false
	if r.state.Fence != "" {
		return r.state.Fence
	}
	return code
}
func (r *Reconciliation) save(ctx context.Context, b *Budget, next coverageState) error {
	if r.bad || !r.bound() || b.check(ctx) != nil {
		return r.failure(roomUnavailable)
	}
	visible, err := os.Lstat(r.file.Name())
	opened, e := r.file.Stat()
	if err != nil || e != nil || !private(visible, 0600) || !os.SameFile(visible, opened) || opened.Size() != r.size {
		r.bad = true
		return r.failure(roomUnavailable)
	}
	delta := next
	if len(next.Receipts) < len(r.state.Receipts) {
		return r.failure(roomUnavailable)
	}
	delta.Receipts = next.Receipts[len(r.state.Receipts):]
	record := checkpoint{r.binding, r.digest, delta}
	encoded, err := json.Marshal(record)
	if err != nil {
		return r.failure(roomUnavailable)
	}
	raw, err := json.Marshal(journalRecord{record, digest(encoded)})
	if err != nil || len(raw) >= 16*1024*1024 {
		return r.failure(roomUnavailable)
	}
	if b.check(ctx) != nil {
		return r.failure(roomUnavailable)
	}
	r.bad = true
	n, err := r.file.Write(append(bytes.Clone(raw), '\n'))
	if err != nil || n != len(raw)+1 || r.file.Sync() != nil {
		return r.failure(roomUnavailable)
	}
	r.state = next
	r.digest = digest(raw)
	r.size += int64(n)
	r.bad = false
	if b.check(ctx) != nil {
		return r.failure(roomUnavailable)
	}
	return nil
}
func (r *Reconciliation) fence(ctx context.Context, b *Budget, code ReadinessCode, id string) error {
	next := r.state
	next.Fence = code
	next.Offender = id
	// Retain the observed fence in memory even when persistence fails. A failed
	// write poisons the journal; restart cannot silently repair a partial record.
	err := r.save(ctx, b, next)
	r.state.Fence = code
	r.state.Offender = id
	if err != nil {
		r.bad = true
	}
	return r.failure(code)
}

// Readiness retains the diagnostic independently of Complete's delivery error.
// An empty code is an observation only, never authority to release a token.
func (r *Reconciliation) Readiness() ReadinessCode {
	if r.state.Fence != "" {
		return r.state.Fence
	}
	if !r.c.ready && r.diagnostic == "" {
		return roomUnavailable
	}
	return r.diagnostic
}

func (r *Reconciliation) bound() bool {
	if r.c.binding == nil {
		return false
	}
	opened, err := r.c.binding.Stat()
	visible, e := os.Lstat(r.c.cfg.BindingPath)
	if err != nil || e != nil || !private(visible, 0600) || !os.SameFile(opened, visible) {
		return false
	}
	raw, err := io.ReadAll(io.NewSectionReader(r.c.binding, 0, 65537))
	return err == nil && len(raw) <= 65536 && digest(raw) == r.binding
}
