package adapters

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// Shallow metadata must not hide a real parent when all objects exist. Missing
// actual parent objects still fail closed, rather than inventing an ancestor.
func TestGitShallowBoundary(t *testing.T) {
	f := newGitFixture(t)
	old := f.pin
	f.commit(t, true)
	g := f.adapter(t)
	for _, metadata := range []string{f.pin + "\n", "invalid shallow metadata\n"} {
		write(t, filepath.Join(f.dir, ".git/shallow"), []byte(metadata), 0600)
		ok, err := g.Descends(f.pin, old)
		if err != nil || !ok {
			t.Fatal("local shallow file hid real ancestry")
		}
	}
	if err := os.Remove(filepath.Join(f.dir, ".git/objects", old[:2], old[2:])); err != nil {
		t.Fatal("remove fixture parent object")
	}
	_, err := g.Descends(f.pin, old)
	wantCode(t, err, registry.RegistryUnavailable)
}

// Alternate stores may supply the pinned objects, but not maintainer authority.
// A wrong-signer commit present in an alternate is still rejected, and returning
// to the approved pin succeeds. An alternateRefsCommand trap must never execute.
func TestGitAlternateObjectTrust(t *testing.T) {
	f := newGitFixture(t)
	other := newGitFixture(t)
	g := f.adapter(t)
	objects := filepath.Join(f.dir, ".git/objects")
	borrowed := filepath.Join(tempDir(t), "objects")
	if err := os.Rename(objects, borrowed); err != nil {
		t.Fatal("move fixture object store")
	}
	if err := os.MkdirAll(filepath.Join(objects, "info"), 0700); err != nil {
		t.Fatal("alternate fixture directory")
	}
	write(t, filepath.Join(objects, "info/alternates"), []byte(borrowed+"\n"+filepath.Join(other.dir, ".git/objects")+"\n"), 0600)
	marker := filepath.Join(tempDir(t), "executed")
	trap := filepath.Join(filepath.Dir(marker), "trap")
	write(t, trap, []byte("#!/bin/sh\nprintf invoked > '"+marker+"'\nexit 0\n"), 0700)
	command(t, f.dir, "git", "config", "core.alternateRefsCommand", trap)
	if entries, err := g.Read(context.Background()); err != nil || len(entries) != 1 || !bytes.Equal(entries[0].Bytes, []byte("first")) {
		t.Fatal("pinned alternate control")
	}
	g.pin = other.pin
	_, err := g.Read(context.Background())
	wantCode(t, err, registry.RegistryUnavailable)
	g.pin = f.pin
	if _, err = g.Read(context.Background()); err != nil {
		t.Fatal("approved alternate control")
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("alternate refs program ran")
	}
}

// A repository-configured promisor transport cannot run on missing objects,
// even with an explicit local protocol allowance. The trap is local-only; the
// signed present object remains readable without consulting any remote.
func TestGitPromisorNoFetch(t *testing.T) {
	f := newGitFixture(t)
	g := f.adapter(t)
	marker := filepath.Join(tempDir(t), "fetched")
	trap := filepath.Join(filepath.Dir(marker), "trap")
	write(t, trap, []byte("#!/bin/sh\nprintf invoked > '"+marker+"'\nexit 1\n"), 0700)
	for _, setting := range [][2]string{{"core.repositoryFormatVersion", "1"}, {"extensions.partialClone", "origin"}, {"remote.origin.promisor", "true"}, {"remote.origin.url", "ext::" + trap}, {"protocol.ext.allow", "always"}} {
		command(t, f.dir, "git", "config", setting[0], setting[1])
	}
	g.pin = strings.Repeat("f", 40)
	_, err := g.Read(context.Background())
	wantCode(t, err, registry.RegistryUnavailable)
	g.pin = f.pin
	if _, err = g.Read(context.Background()); err != nil {
		t.Fatal("present signed object control")
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("promisor transport invoked")
	}
}

// A validly checksummed but forged local commit-graph must not add ancestry.
// The fixture first proves ordinary Git consumes the forgery; the adapter must
// return false for the signed independent history and true for a real descendant.
func TestGitForgedCommitGraph(t *testing.T) {
	f := newGitFixture(t)
	old := f.pin
	tree := command(t, f.dir, "git", "rev-parse", old+"^{tree}")
	root := command(t, f.dir, "git", "commit-tree", "-S", "-m", "Independent graph fixture", tree)
	candidate := command(t, f.dir, "git", "commit-tree", "-S", "-p", root, "-m", "Independent graph child", tree)
	command(t, f.dir, "git", "update-ref", "refs/heads/independent", candidate)
	command(t, f.dir, "git", "-c", "commitGraph.generationVersion=1", "commit-graph", "write", "--reachable", "--no-progress")
	path := filepath.Join(f.dir, ".git/objects/info/commit-graph")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read fixture graph")
	}
	// Git's documented v1 SHA-1 graph: OIDL sorted IDs; CDAT tree ID,
	// parent positions and generation/time; trailing SHA-1 checksum.
	// https://git-scm.com/docs/gitformat-commit-graph
	if len(raw) < 8+20 || string(raw[:4]) != "CGPH" || raw[4] != 1 || raw[5] != 1 || raw[7] != 0 {
		t.Fatal("fixture graph format")
	}
	chunks := map[string]int{}
	for i := 0; i < int(raw[6]); i++ {
		at := 8 + i*12
		if at+12 > len(raw)-20 {
			t.Fatal("fixture chunk table")
		}
		offset := binary.BigEndian.Uint64(raw[at+4 : at+12])
		if offset > uint64(len(raw)-20) {
			t.Fatal("fixture chunk offset")
		}
		chunks[string(raw[at:at+4])] = int(offset)
	}
	oidl, cdat := chunks["OIDL"], chunks["CDAT"]
	if oidl == 0 || cdat <= oidl || (cdat-oidl)%20 != 0 {
		t.Fatal("fixture graph chunks")
	}
	find := func(id string) int {
		want, err := hex.DecodeString(id)
		if err != nil {
			t.Fatal("fixture object ID")
		}
		for i := 0; i < (cdat-oidl)/20; i++ {
			if bytes.Equal(raw[oidl+i*20:oidl+(i+1)*20], want) {
				return i
			}
		}
		t.Fatal("fixture graph missing object")
		return -1
	}
	parent, forged := find(old), find(root)
	row := cdat + forged*36
	if row+36 > len(raw)-20 {
		t.Fatal("fixture graph row")
	}
	binary.BigEndian.PutUint32(raw[row+20:row+24], uint32(parent))
	stamp := binary.BigEndian.Uint32(raw[row+28 : row+32])
	binary.BigEndian.PutUint32(raw[row+28:row+32], (2<<2)|(stamp&3))
	childRow := cdat + find(candidate)*36
	if childRow+36 > len(raw)-20 {
		t.Fatal("fixture child row")
	}
	stamp = binary.BigEndian.Uint32(raw[childRow+28 : childRow+32])
	binary.BigEndian.PutUint32(raw[childRow+28:childRow+32], (3<<2)|(stamp&3))
	checksum := sha1.Sum(raw[:len(raw)-20]) // Format checksum only, not a signing key.
	copy(raw[len(raw)-20:], checksum[:])
	write(t, path, raw, 0600)
	command(t, f.dir, "git", "-c", "core.commitGraph=true", "merge-base", "--is-ancestor", old, candidate)
	f.pin = candidate
	g := f.adapter(t)
	if ok, err := g.Descends(candidate, old); err != nil || ok {
		t.Fatal("forged graph became ancestry authority")
	}
	command(t, f.dir, "git", "config", "core.commitGraph", "true")
	descendant := command(t, f.dir, "git", "-c", "core.commitGraph=false", "commit-tree", "-S", "-p", old, "-m", "Real graph descendant", tree)
	g.pin = descendant
	if ok, err := g.Descends(descendant, old); err != nil || !ok {
		t.Fatal("real graph descendant control")
	}
}
