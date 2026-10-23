// Package admission implements spec §§6.1–9, rows 8–21, without live adapters.
// Callers pass unmodified verified registration.Parse results and immutable registry
// snapshots under the same configured audience/pins. HTTP checks 1–7 stay outside.
package admission

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/registry"
)

// Reading supplies floored UTC seconds and monotonic process elapsed time.
// Faulted must latch any sync loss/backward UTC step since process start, even
// between observations. The adapter must not omit transient faults. The core
// additionally detects observed UTC/monotonic regression and permanently fences.
type Reading struct {
	UTC              int64
	Monotonic        time.Duration
	Healthy, Faulted bool
}

// Startup carries actual process-start evidence, not constructor-call time.
// Ordered attests synchronized start UTC no earlier than ANY previous admission
// (§7). A startup premise that cannot be established leaves this process fenced.
type Startup struct {
	Reading Reading
	Ordered bool
}

// Clock supplies clock evidence and finite monotonic watchdogs. Deadline must
// preserve parent cancellation, cancel at the given monotonic instant and never
// use UTC for intervals. No real clock implementation is included in this package.
type Clock interface {
	Now() Reading
	Deadline(context.Context, time.Duration) (context.Context, context.CancelFunc)
}

// Signer is an immutable Ed25519 key generation. The caller owns protected key
// custody and coordinated homeserver cutover (§8). PublicKey is nonblocking and
// Sign must respect context cancellation. The core verifies the returned signature.
type Signer interface {
	PublicKey() ed25519.PublicKey
	Sign(context.Context, []byte) ([]byte, error)
}

// AuditHead is the reconciled durable local chain tip, retained across restarts.
type AuditHead struct {
	Sequence int64
	Hash     string
}

// Audit owns bounded external operations (§9). Append must validate increasing
// sequence/hash continuity and durably commit the EXACT LF-terminated line before
// success. Errors must not claim a commit; ambiguous local state requires recovery.
// Acknowledge must obtain authenticated durable off-host acknowledgement of that
// exact line (shipping any prerequisite spooled lines in order). Concurrent calls
// are allowed. Probe verifies local recording health and the exact retained head
// without writing. All methods must honor context cancellation. No sink is provided.
type Audit interface {
	Append(context.Context, []byte) error
	Acknowledge(context.Context, []byte) error
	Probe(context.Context, AuditHead) error
}

// Limits are whole-number capacities; nil Config.Limits selects 10/key, 3/name.
// Explicit capacities must be 1..10 and 1..3; a configuration decoder must not
// coerce fractional input to these integer fields.
type Limits struct{ PerKey, PerName int }
type Config struct {
	Audience string
	Clock    Clock
	Startup  Startup
	Registry *registry.Snapshot
	Signer   Signer
	Audit    Audit
	Head     AuditHead
	Instance [16]byte // Caller supplies a random process identifier; tests use public fixed bytes.
	Limits   *Limits
	Timeout  time.Duration // Zero selects the five-second total request deadline.
}

// Request contains the caller's verified proof and observed bytes. The caller
// must not mutate Proof concurrently; the core copies it on entry. No raw input
// is retained or audited, and the observed count is capped at 65,537 for audit.
type Request struct {
	Proof *registration.Body
	Bytes uint64
}

// Error is one typed refusal. RetryAfter is positive only for a rate limit.
type Error struct {
	Code       refusal.Code
	RetryAfter int64
}

func (e *Error) Error() string           { return string(e.Code) }
func (e *Error) Unwrap() error           { return refusal.New(e.Code) }
func deny(code refusal.Code) *Error      { return &Error{Code: code} }
func invalidConfig(message string) error { return fmt.Errorf("admission configuration: %s", message) }
