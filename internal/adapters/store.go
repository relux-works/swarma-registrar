package adapters

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/internal/enrollment"
	"github.com/relux-works/swarma-registrar/internal/revision"
	"github.com/relux-works/swarma-registrar/registry"
)

const maxWaterBytes = 64 * 1024 * 1024

// Stored never attests freshness. A local file, including a successful local
// write, cannot establish reconciliation after process start or restoration.
type Stored struct {
	HighWater  *registry.HighWater
	Reconciled bool
}
type diskWater struct {
	Version int64              `json:"v"`
	Water   registry.HighWater `json:"high_water"`
}

func waterBytes(w *registry.HighWater, objectFormat string) ([]byte, error) {
	if w == nil || !revision.Valid(objectFormat, w.Revision) || w.Hosts == nil || w.KeyOwners == nil || w.NameOwners == nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	for host, h := range w.Hosts {
		if !enrollment.ValidHost(host) || h.Seq < 1 || h.Seq > 9007199254740991 || !auditID.MatchString(h.ID) || len(h.History) == 0 || h.History[h.Seq] != h.ID {
			return nil, failure(registry.RegistryUnavailable)
		}
		for seq, id := range h.History {
			if seq < 1 || seq > h.Seq || !auditID.MatchString(id) {
				return nil, failure(registry.RegistryUnavailable)
			}
		}
	}
	for _, owners := range []map[string]string{w.KeyOwners, w.NameOwners} {
		for _, host := range owners {
			if _, ok := w.Hosts[host]; !ok {
				return nil, failure(registry.RegistryUnavailable)
			}
		}
	}
	raw, err := json.Marshal(diskWater{1, *w})
	if err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	value, err := ccj.Parse(raw, registry.RegistryUnavailable)
	if err != nil {
		return nil, err
	}
	encoded, err := ccj.Marshal(value, registry.RegistryUnavailable)
	if err != nil || len(encoded) > maxWaterBytes {
		return nil, failure(registry.RegistryUnavailable)
	}
	return encoded, nil
}
func decodeWater(raw []byte, objectFormat string) (*registry.HighWater, error) {
	parsed, err := ccj.Parse(raw, registry.RegistryUnavailable)
	if err != nil {
		return nil, err
	}
	canonical, err := ccj.Marshal(parsed, registry.RegistryUnavailable)
	if err != nil {
		return nil, err
	}
	var disk diskWater
	if err = json.Unmarshal(canonical, &disk); err != nil || disk.Version != 1 {
		return nil, failure(registry.RegistryUnavailable)
	}
	expected, err := waterBytes(&disk.Water, objectFormat)
	// Re-encoding requires every field, exact field case, no unknown members or
	// ambiguous null maps; the codec never silently drops durable evidence.
	if err != nil || !bytes.Equal(expected, canonical) || !bytes.Equal(raw, canonical) {
		return nil, failure(registry.RegistryUnavailable)
	}
	return disk.Water.Clone(), nil
}

// FileStore serializes cooperating writers with a stable no-follow flock file.
// Any failure leaves durability indeterminate; no compensating rename is tried.
// Callers fence admission. Load always returns unreconciled local evidence.
type FileStore struct {
	mu           sync.Mutex
	path         string
	objectFormat string
	before       func(string) error
}

func NewFileStore(path, objectFormat string) (*FileStore, error) {
	if revision.Size(objectFormat) == 0 || !absolute(path) || !privateDirectory(filepath.Dir(path)) {
		return nil, failure(registry.RegistryUnavailable)
	}
	return &FileStore{path: path, objectFormat: objectFormat}, nil
}
func (s *FileStore) step(name string) error {
	if s.before != nil {
		if err := s.before(name); err != nil {
			return failure(registry.RegistryUnavailable)
		}
	}
	return nil
}
func (s *FileStore) read() (*registry.HighWater, error) {
	f, err := nofollow(s.path, syscall.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateFile(info) {
		return nil, failure(registry.RegistryUnavailable)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxWaterBytes+1))
	if err != nil || len(raw) > maxWaterBytes {
		return nil, failure(registry.RegistryUnavailable)
	}
	injected := s.step("read_close")
	if err := f.Close(); err != nil || injected != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	return decodeWater(raw, s.objectFormat)
}
func (s *FileStore) Load() (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	water, err := s.read()
	if err != nil || water == nil {
		return Stored{}, failure(registry.RegistryUnavailable)
	}
	return Stored{HighWater: water, Reconciled: false}, nil
}

// Inspect exposes local evidence, including explicit absence, without attesting
// freshness or authorizing bootstrap. Only an operator can make those decisions.
func (s *FileStore) Inspect() (*registry.HighWater, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

// HighWaterDigest identifies the exact canonical durable encoding, not its
// freshness. An absent or invalid state has no high-water digest.
func HighWaterDigest(w *registry.HighWater, objectFormat string) (string, error) {
	raw, err := waterBytes(w, objectFormat)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func (s *FileStore) Commit(previous *registry.HighWater, next registry.HighWater) (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bad := func() error { return failure(registry.RegistryUnavailable) }
	if s.step("lock") != nil {
		return bad()
	}
	lock, err := nofollow(s.path+".lock", syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		return bad()
	}
	defer func() {
		injected := s.step("lock_close")
		if err := lock.Close(); err != nil || injected != nil {
			result = bad()
		}
	}()
	info, err := lock.Stat()
	if err != nil || !privateFile(info) {
		return bad()
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return bad()
	}
	defer func() {
		injected := s.step("unlock")
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil || injected != nil {
			result = bad()
		}
	}()
	if s.step("read") != nil {
		return bad()
	}
	current, err := s.read()
	if err != nil {
		return bad()
	}
	if (current == nil) != (previous == nil) {
		return bad()
	}
	if current != nil {
		a, err := waterBytes(current, s.objectFormat)
		if err != nil {
			return bad()
		}
		b, err := waterBytes(previous, s.objectFormat)
		if err != nil || !bytes.Equal(a, b) {
			return bad()
		}
	}
	data, err := waterBytes(next.Clone(), s.objectFormat)
	if err != nil {
		return bad()
	}
	if s.step("create") != nil {
		return bad()
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), ".water-*")
	if err != nil {
		return bad()
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if s.step("write") != nil {
		return bad()
	}
	if n, err := temp.Write(data); err != nil || n != len(data) {
		return bad()
	}
	if s.step("file_sync") != nil {
		return bad()
	}
	if err = temp.Sync(); err != nil {
		return bad()
	}
	if s.step("close") != nil {
		return bad()
	}
	if err = temp.Close(); err != nil {
		return bad()
	}
	if s.step("rename") != nil {
		return bad()
	}
	if err = os.Rename(temp.Name(), s.path); err != nil {
		return bad()
	}
	if s.step("directory_open") != nil {
		return bad()
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return bad()
	}
	if s.step("directory_sync") != nil {
		dir.Close()
		return bad()
	}
	if err = dir.Sync(); err != nil {
		dir.Close()
		return bad()
	}
	injected := s.step("directory_close")
	if err = dir.Close(); err != nil || injected != nil {
		return bad()
	}
	return nil
}

var _ registry.Store = (*FileStore)(nil)
