package adapters

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
)

type custodyRemote struct {
	action func()
	calls  int
}

func (r *custodyRemote) Commit(_ context.Context, line []byte) ([32]byte, error) {
	r.calls++
	if r.action != nil {
		r.action()
	}
	return sha256.Sum256(line), nil
}

// Lost identity, unsafe permissions, truncation and same-length edits must fail
// before shipping, during a remote call and on the deduplicated path. The fence
// survives restoration until explicit exact-head Probe; an intact control then
// succeeds. All faults affect only temporary fixture files.
func TestAuditCustodyBoundaries(t *testing.T) {
	for _, timing := range []string{"before", "during", "deduplicated"} {
		for _, kind := range []string{"unlink", "replace", "unsafe-mode", "truncate", "same-length-edit"} {
			t.Run(timing+"/"+kind, func(t *testing.T) {
				remote := &custodyRemote{}
				a, path := auditFixture(t, remote)
				line := auditLine(t, 1, strings.Repeat("0", 64))
				if err := a.Append(context.Background(), line); err != nil {
					t.Fatal("durable append")
				}
				head := a.Head()
				backup := path + ".saved"
				if err := os.Link(path, backup); err != nil {
					t.Fatal("retain fixture inode")
				}
				change := func() {
					var err error
					switch kind {
					case "unlink":
						err = os.Remove(path)
					case "replace":
						err = os.Remove(path)
						if err == nil {
							err = os.WriteFile(path, line, 0600)
						}
					case "unsafe-mode":
						err = os.Chmod(path, 0644)
					case "truncate":
						err = os.Truncate(path, 0)
					case "same-length-edit":
						changed := editAudit(t, line, func(m map[string]any) { m["request_bytes"] = int64(1) })
						if len(changed) != len(line) {
							t.Fatal("edit must preserve size")
						}
						err = os.WriteFile(path, changed, 0600)
					}
					if err != nil {
						t.Fatal("fixture custody fault")
					}
				}
				if timing == "deduplicated" {
					if err := a.Acknowledge(context.Background(), line); err != nil {
						t.Fatal("initial intact ack")
					}
				}
				beforeCalls := remote.calls
				if timing == "during" {
					remote.action = change
				} else {
					change()
				}
				wantCode(t, a.Acknowledge(context.Background(), line), auditUnavailable)
				if timing != "during" && remote.calls != beforeCalls {
					t.Fatal("unusable local state shipped")
				}
				if !a.bad || a.Head() != head {
					t.Fatal("custody fault not fenced at retained head")
				}
				remote.action = nil
				if kind == "unlink" || kind == "replace" {
					if kind == "replace" {
						if err := os.Remove(path); err != nil {
							t.Fatal("remove replacement")
						}
					}
					if err := os.Link(backup, path); err != nil {
						t.Fatal("restore fixture pathname")
					}
				}
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal("restore fixture permissions")
				}
				if err := os.WriteFile(path, line, 0600); err != nil {
					t.Fatal("restore fixture bytes")
				}
				wantCode(t, a.Acknowledge(context.Background(), line), auditUnavailable)
				wantCode(t, a.Append(context.Background(), auditLine(t, 2, head.Hash)), auditUnavailable)
				if err := a.Probe(context.Background(), head); err != nil {
					t.Fatal("explicit exact-head recovery")
				}
				if err := a.Acknowledge(context.Background(), line); err != nil {
					t.Fatal("intact recovered control")
				}
			})
		}
	}
}
