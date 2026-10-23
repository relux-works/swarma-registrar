package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A real child session must have both terminal stdin and a controlling terminal;
// pipe/redirection cannot carry confirmation, while the PTY control is accepted.
func TestControllingTerminalOnly(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(input *os.File, withTTY bool) string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTerminalHelper$")
		cmd.Env = append(os.Environ(), "REGISTRAR_TERMINAL_TEST=1")
		cmd.Stdin = input
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if withTTY {
			cmd.SysProcAttr.Setctty = true
			cmd.SysProcAttr.Ctty = 0
		}
		raw, err := cmd.Output()
		if cmd.Process != nil {
			t.Logf("terminal fixture process pid=%d", cmd.Process.Pid)
		}
		if err != nil {
			t.Fatalf("terminal helper: %v", err)
		}
		return string(raw)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	write.Close()
	if got := run(read, false); !strings.Contains(got, "refused") {
		t.Fatal("pipe accepted")
	}
	master, slave := pty(t)
	defer master.Close()
	defer slave.Close()
	if got := run(slave, true); !strings.Contains(got, "accepted") {
		t.Fatal("controlling terminal refused")
	}
}

// This isolated subprocess observes the production terminal gate without reading
// confirmation or contacting a service. Only the parent test invokes this mode.
func TestTerminalHelper(t *testing.T) {
	if os.Getenv("REGISTRAR_TERMINAL_TEST") != "1" {
		t.Skip("subprocess helper")
	}
	terminal, err := openTerminal()
	if err != nil {
		fmt.Println("refused")
		return
	}
	terminal.Close()
	fmt.Println("accepted")
}
func pty(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var unlock int32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno != 0 {
		master.Close()
		t.Fatal(errno)
	}
	var number uint32
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number))); errno != 0 {
		master.Close()
		t.Fatal(errno)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	return master, slave
}

// No CLI option or redirected input can substitute for operator confirmation;
// unknown commands/flags and missing config also fail without opening a listener.
func TestCommandRejectsNoninteractiveBypasses(t *testing.T) {
	f := fixture(t)
	d := testDependencies(t, f, false, false)
	for _, args := range [][]string{
		{}, {"reconcile", "--config", "fixture"}, {"serve"},
		{"serve", "--config", "fixture", "--confirmation", f.initialDigest},
		{"serve", "--config", "fixture", "--reconciled"},
		{"serve", "--config", "fixture", "--reconcile=true", "unexpected"},
	} {
		d.listening = func(_ net.Addr) { t.Fatal("invalid command opened listener") }
		if err := run(context.Background(), args, io.Discard, io.Discard, time.Now(), d); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}

// Exact confirmation is read from a real controlling PTY: a wrong line or EOF
// refuses authority, and the exact digest authorizes the same validated fixture.
func TestReconcileThroughControllingTerminal(t *testing.T) {
	for _, answer := range []string{"wrong", "missing", "exact"} {
		t.Run(answer, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			master, slave := pty(t)
			defer master.Close()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTerminalReconcileHelper$")
			cmd.Env = append(os.Environ(), "REGISTRAR_RECONCILE_TEST=1")
			cmd.Stdin = slave
			cmd.Stdout = slave
			cmd.Stderr = slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err = cmd.Start(); err != nil {
				slave.Close()
				t.Fatal(err)
			}
			t.Logf("terminal fixture process pid=%d", cmd.Process.Pid)
			defer func() {
				if cmd.ProcessState == nil {
					cancel()
					_ = cmd.Wait()
				}
			}()
			slave.Close()
			var output strings.Builder
			readUntil := func(marker string) {
				one := make([]byte, 1)
				for !strings.Contains(output.String(), marker) {
					n, err := master.Read(one)
					if n > 0 {
						output.Write(one[:n])
					}
					if err != nil {
						t.Fatalf("terminal output before %q: %v: %s", marker, err, output.String())
					}
					if output.Len() > 8192 {
						t.Fatal("terminal output bound")
					}
				}
			}
			readUntil("this process only: ")
			text := output.String()
			index := strings.LastIndex(text, "Type exactly ")
			if index < 0 {
				t.Fatal("no digest prompt")
			}
			digest := strings.Fields(text[index:])[2]
			input := "wrong\n"
			if answer == "missing" {
				input = "\x04"
			}
			if answer == "exact" {
				input = digest + "\n"
			}
			if _, err = io.WriteString(master, input); err != nil {
				t.Fatal(err)
			}
			marker := "FENCED"
			if answer == "exact" {
				marker = "AUTHORIZED"
			}
			readUntil(marker)
			if err = cmd.Wait(); err != nil {
				t.Fatalf("terminal child: %v: %s", err, output.String())
			}
		})
	}
}

// The subprocess installs only disposable deterministic fixtures and delegates
// input to the production controlling-terminal opener, without a CLI bypass.
func TestTerminalReconcileHelper(t *testing.T) {
	if os.Getenv("REGISTRAR_RECONCILE_TEST") != "1" {
		t.Skip("subprocess helper")
	}
	f := fixture(t)
	snapshot, err := reconcile(context.Background(), f.config, f.source, f.store, openTerminal, os.Stdout)
	if err != nil || snapshot == nil {
		fmt.Println("FENCED")
		return
	}
	fmt.Println("AUTHORIZED")
}
