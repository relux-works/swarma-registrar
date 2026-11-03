package matrixaudit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-registrar/ccj"
)

type bindingFile struct{ *os.File }

func private(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid() && info.Mode() == mode
}
func (c *Client) startup(ctx context.Context, b *Budget, nonempty bool, emptyRoom func(context.Context, *Budget) error) error {
	if b.check(ctx) != nil {
		return roomUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, b.deadline)
	defer cancel()
	who, err := c.request(ctx, b, "GET", []string{"account", "whoami"}, nil)
	if err != nil {
		return roomUnavailable
	}
	device, ok := who["device_id"].(string)
	if !ok || device == "" {
		return roomUnavailable
	}
	if who["user_id"] != c.cfg.User {
		return errors.New("audit_room_policy_invalid")
	}
	path := c.cfg.BindingPath
	if !filepath.IsAbs(path) {
		return roomUnavailable
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !private(info, os.ModeDir|0700) {
		return roomUnavailable
	}
	want := map[string]any{"origin": c.cfg.Origin, "room": c.cfg.Room, "user": c.cfg.User, "device": device, "initial_empty_room": true}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	fresh := false
	if err == syscall.ENOENT {
		if nonempty || emptyRoom == nil || emptyRoom(ctx, b) != nil || b.check(ctx) != nil {
			return roomUnavailable
		}
		fd, err = syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		fresh = true
	}
	if err != nil {
		return roomUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func() error { f.Close(); return roomUnavailable }
	info, err = f.Stat()
	if err != nil || !private(info, 0600) || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	if fresh {
		raw, e := json.Marshal(want)
		if e != nil {
			return fail()
		}
		n, e := f.Write(raw)
		if e != nil || n != len(raw) || f.Sync() != nil {
			return fail()
		}
		directory, e := os.Open(dir)
		if e != nil {
			return fail()
		}
		e = directory.Sync()
		closeErr := directory.Close()
		if e != nil || closeErr != nil {
			return fail()
		}
	} else {
		raw, e := io.ReadAll(io.LimitReader(f, 65537))
		if e != nil || len(raw) > 65536 {
			return fail()
		}
		value, e := ccj.Parse(raw, "audit_room_unavailable")
		if e != nil {
			return fail()
		}
		got, ok := value.(map[string]any)
		if !ok || len(got) != len(want) {
			return fail()
		}
		for k, v := range want {
			if got[k] != v {
				return fail()
			}
		}
	}
	if b.check(ctx) != nil {
		return fail()
	}
	c.binding = &bindingFile{f}
	c.ready = true
	return nil
}
