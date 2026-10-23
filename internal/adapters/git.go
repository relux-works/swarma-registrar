package adapters

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/registry"
)

var revisionPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func fullRevision(s string) bool { return revisionPattern.MatchString(s) }

// Git reads only immutable objects from one configured local repository/pin.
// SSH signatures use a protected allowed-signers file, never repository trust
// settings or a user keyring. Commands cannot fetch, prompt, invoke a shell,
// use replace refs, or read global/system Git configuration.
type Git struct{ repository, pin, signers, git, ssh string }

func NewGit(repository, pin, allowedSigners string) (*Git, error) {
	return newGit(repository, pin, allowedSigners, protected)
}
func newGit(repository, pin, allowedSigners string, guard func(os.FileInfo, int) bool) (*Git, error) {
	if !absolute(repository) || !absolute(allowedSigners) || !fullRevision(pin) {
		return nil, failure(registry.RegistryUnavailable)
	}
	if _, err := readProtectedWith(allowedSigners, 65536, guard); err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	ssh, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	return &Git{repository, pin, allowedSigners, git, ssh}, nil
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}
func (g *Git) run(ctx context.Context, limit int, args ...string) ([]byte, error) {
	fixed := []string{"--no-replace-objects", "-C", g.repository, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=" + g.ssh, "-c", "gpg.ssh.allowedSignersFile=" + g.signers, "-c", "gpg.ssh.revocationFile=/dev/null", "-c", "gpg.minTrustLevel=fully"}
	cmd := exec.CommandContext(ctx, g.git, append(fixed, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0"}
	out := &boundedOutput{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return out.Bytes(), err
}
func (g *Git) verify(ctx context.Context) error {
	kind, err := g.run(ctx, 64, "cat-file", "-t", g.pin)
	if err != nil || string(kind) != "commit\n" {
		return failure(registry.RegistryUnavailable)
	}
	if _, err = g.run(ctx, 4096, "verify-commit", g.pin); err != nil {
		return failure(registry.RegistryUnavailable)
	}
	return nil
}

// Read authenticates the commit and returns complete first-level JSON blobs.
// It never reads the working tree, follows a ref or performs an implicit fetch.
func (g *Git) Read(parent context.Context) ([]registry.Entry, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := g.verify(ctx); err != nil {
		return nil, err
	}
	raw, err := g.run(ctx, 4*1024*1024, "ls-tree", "-r", "-t", "-z", g.pin, "--", "enrollments")
	if err != nil {
		return nil, failure(registry.RegistryUnavailable)
	}
	type blob struct {
		path, id string
		size     int64
	}
	var blobs []blob
	var total int64
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		pair := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(pair) != 2 {
			return nil, failure(registry.RegistryUnavailable)
		}
		meta := strings.Fields(string(pair[0]))
		path := string(pair[1])
		if len(meta) != 3 {
			return nil, failure(registry.RegistryUnavailable)
		}
		if path == "enrollments" {
			if meta[0] != "040000" || meta[1] != "tree" {
				return nil, failure(registry.RegistryUnavailable)
			}
			continue
		}
		if !strings.HasPrefix(path, "enrollments/") || strings.Contains(strings.TrimPrefix(path, "enrollments/"), "/") || !strings.HasSuffix(path, ".json") {
			continue
		}
		if (meta[0] != "100644" && meta[0] != "100755") || meta[1] != "blob" || !fullRevision(meta[2]) {
			return nil, failure(registry.RegistryUnavailable)
		}
		sizeRaw, err := g.run(ctx, 64, "cat-file", "-s", meta[2])
		if err != nil {
			return nil, failure(registry.RegistryUnavailable)
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(sizeRaw)), 10, 64)
		if err != nil || size < 0 {
			return nil, failure(registry.RegistryUnavailable)
		}
		total += size
		blobs = append(blobs, blob{path, meta[2], size})
		if len(blobs) > registry.MaxEntries || total > registry.MaxBytes {
			return nil, failure(registry.RegistryUnavailable)
		}
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].path < blobs[j].path })
	entries := make([]registry.Entry, 0, len(blobs))
	for _, blob := range blobs {
		if blob.size > 65536 {
			return nil, &registry.Diagnostic{Code: registry.EnrollmentMalformed, Path: blob.path}
		}
		data, err := g.run(ctx, 65536, "cat-file", "blob", blob.id)
		if err != nil || int64(len(data)) != blob.size {
			return nil, failure(registry.RegistryUnavailable)
		}
		entries = append(entries, registry.Entry{Path: blob.path, Bytes: bytes.Clone(data), Kind: registry.Regular})
	}
	return entries, nil
}
func (g *Git) Verify(revision string, entries []registry.Entry) error {
	if revision != g.pin {
		return failure(registry.RegistryUnavailable)
	}
	expected, err := g.Read(context.Background())
	if err != nil {
		return err
	}
	supplied := append([]registry.Entry(nil), entries...)
	sort.Slice(supplied, func(i, j int) bool { return supplied[i].Path < supplied[j].Path })
	if len(supplied) != len(expected) {
		return failure(registry.RegistryUnavailable)
	}
	for i, entry := range expected {
		if supplied[i].Path != entry.Path || supplied[i].Kind != entry.Kind || !bytes.Equal(supplied[i].Bytes, entry.Bytes) {
			return failure(registry.RegistryUnavailable)
		}
	}
	return nil
}
func (g *Git) Descends(candidate, previous string) (bool, error) {
	if candidate != g.pin || !fullRevision(previous) {
		return false, failure(registry.RegistryUnavailable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kind, err := g.run(ctx, 64, "cat-file", "-t", previous)
	if err != nil || string(kind) != "commit\n" {
		return false, failure(registry.RegistryUnavailable)
	}
	_, err = g.run(ctx, 64, "merge-base", "--is-ancestor", previous, candidate)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, failure(registry.RegistryUnavailable)
}

var _ registry.Verifier = (*Git)(nil)
