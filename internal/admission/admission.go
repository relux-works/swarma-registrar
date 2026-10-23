package admission

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"sync"
	"time"

	"github.com/relux-works/swarma-registrar/internal/keys"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
	"github.com/relux-works/swarma-registrar/registry"
)

type nonceID struct {
	key   string
	nonce [16]byte
}
type signing struct {
	signer     Signer
	public     ed25519.PublicKey
	generation uint64
	paused     bool
}

// Admitter owns one process's authority, accounting, clock fence and audit chain.
// New instances model real verified restarts, never a way to clear live fences.
type Admitter struct {
	mu                       sync.Mutex
	clock                    Clock
	audience                 string
	barrier                  int64
	last                     Reading
	clockFenced, auditFenced bool
	snapshot                 *registry.Snapshot
	signing                  signing
	limits                   Limits
	timeout                  time.Duration
	nonces                   map[nonceID]int64
	keyEvents, nameEvents    map[string][]time.Duration
	auditGate                chan struct{} // Cancellable local sequencing; never held during off-host I/O.
	sink                     Audit
	head                     AuditHead
	instance                 string
}

func New(c Config) (*Admitter, error) {
	if c.Clock == nil || c.Audit == nil || c.Audience == "" {
		return nil, invalidConfig("clock, audit and canonical audience required")
	}
	limits := Limits{10, 3}
	if c.Limits != nil {
		limits = *c.Limits
	}
	if limits.PerKey < 1 || limits.PerKey > 10 || limits.PerName < 1 || limits.PerName > 3 {
		return nil, invalidConfig("invalid capacities")
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Timeout < 0 {
		return nil, invalidConfig("invalid deadline")
	}
	if c.Head.Sequence == 0 && c.Head.Hash == "" {
		c.Head.Hash = zeroHash()
	}
	if !validHead(c.Head) {
		return nil, invalidConfig("invalid audit head")
	}
	if !validUTC(c.Startup.Reading.UTC) || c.Startup.Reading.Monotonic < 0 {
		return nil, invalidConfig("invalid process start")
	}
	a := &Admitter{auditGate: make(chan struct{}, 1), clock: c.Clock, audience: c.Audience, barrier: c.Startup.Reading.UTC + 31, last: c.Startup.Reading, snapshot: c.Registry, limits: limits, timeout: c.Timeout, nonces: map[nonceID]int64{}, keyEvents: map[string][]time.Duration{}, nameEvents: map[string][]time.Duration{}, sink: c.Audit, head: c.Head, instance: base64.RawURLEncoding.EncodeToString(c.Instance[:])}
	a.clockFenced = !c.Startup.Ordered || !c.Startup.Reading.Healthy || c.Startup.Reading.Faulted
	a.signing = signing{signer: c.Signer, public: signingPublic(c.Signer), generation: 1}
	return a, nil
}
func signingPublic(s Signer) ed25519.PublicKey {
	if s == nil {
		return nil
	}
	p := s.PublicKey()
	if len(p) != 32 || !keys.ValidEd25519Point(p) {
		return nil
	}
	return append(ed25519.PublicKey(nil), p...)
}

// Publish must be called for every registry replacement/fence; nil means unavailable.
// It shares the release lock. The caller only supplies approved persisted snapshots.
func (a *Admitter) Publish(s *registry.Snapshot) { a.mu.Lock(); defer a.mu.Unlock(); a.snapshot = s }
func (a *Admitter) PauseSigning()                { a.mu.Lock(); defer a.mu.Unlock(); a.signing.paused = true }

// Cutover always pauses and advances the generation. The caller coordinates the
// protected key/homeserver switch, then explicitly resumes; pending old tokens
// are cancelled, never drained or implicitly re-signed (§10).
func (a *Admitter) Cutover(s Signer) {
	p := signingPublic(s)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signing.generation++
	a.signing.signer = s
	a.signing.public = p
	a.signing.paused = true
}
func (a *Admitter) ResumeSigning() { a.mu.Lock(); defer a.mu.Unlock(); a.signing.paused = false }
func (a *Admitter) Ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.observe()
	return !a.clockFenced && !a.auditFenced && a.snapshot != nil && !a.signing.paused && a.signing.signer != nil && len(a.signing.public) == 32
}
func validUTC(sec int64) bool { return sec >= 0 && sec <= 253402300799 }
func (a *Admitter) observe() Reading {
	r := a.clock.Now()
	if !r.Healthy || r.Faulted || !validUTC(r.UTC) || r.UTC < a.last.UTC || r.Monotonic < a.last.Monotonic {
		a.clockFenced = true
	}
	a.last = r
	return r
}
func (a *Admitter) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	r := a.clock.Now()
	return a.clock.Deadline(ctx, r.Monotonic+a.timeout)
}

// authority runs exactly rows 8–17 under mu. Audit identity is accumulated only
// after verification reaches the relevant stage. It never debits or reserves.
func (a *Admitter) authority(p *registration.Body, r Reading, m *metadata) *Error {
	if a.snapshot == nil {
		return deny(refusal.RegistryUnavailable)
	}
	revision := a.snapshot.Revision()
	m.revision = &revision
	record, window, ok := a.snapshot.LookupKey(p.Key.Encoding())
	if !ok {
		return deny(refusal.KeyNotEnrolled)
	}
	host := record.Host()
	m.host = &host
	if !window.ValidAt(p.IssuedAt, r.UTC) {
		return deny(refusal.KeyNotValidNow)
	}
	if record.Revoked() {
		return deny(refusal.HostRevoked)
	}
	if err := p.CheckName(a.audience); err != nil {
		return deny(refusal.NameInvalid)
	}
	name := p.Name
	m.name = &name
	if err := record.Permits(p.Name, a.audience); err != nil {
		return deny(refusal.NameNotPermitted)
	}
	if err := p.CheckAudience(a.audience); err != nil {
		return deny(refusal.AudienceMismatch)
	}
	if a.clockFenced || p.IssuedAt < a.barrier {
		return deny(refusal.ClockSkew)
	}
	if p.IssuedAt > r.UTC+30 {
		return deny(refusal.RequestNotYetValid)
	}
	if r.UTC >= p.ExpiresAt+30 {
		return deny(refusal.RequestExpired)
	}
	return nil
}
func prune(events []time.Duration, now time.Duration) []time.Duration {
	i := 0
	for i < len(events) && now-events[i] >= 60*time.Second {
		i++
	}
	return append([]time.Duration(nil), events[i:]...)
}
func (a *Admitter) budget(p *registration.Body, now time.Duration) *Error {
	// Remove empty histories so authenticated name variation cannot grow maps forever.
	for k, v := range a.keyEvents {
		v = prune(v, now)
		if len(v) == 0 {
			delete(a.keyEvents, k)
		} else {
			a.keyEvents[k] = v
		}
	}
	for k, v := range a.nameEvents {
		v = prune(v, now)
		if len(v) == 0 {
			delete(a.nameEvents, k)
		} else {
			a.nameEvents[k] = v
		}
	}
	key := p.Key.Encoding()
	k, n := a.keyEvents[key], a.nameEvents[p.Name]
	wait := time.Duration(0)
	if len(k) >= a.limits.PerKey {
		wait = k[0] + 60*time.Second - now
	}
	if len(n) >= a.limits.PerName {
		d := n[0] + 60*time.Second - now
		if d > wait {
			wait = d
		}
	}
	if wait > 0 {
		return &Error{Code: refusal.RateLimited, RetryAfter: int64((wait + time.Second - 1) / time.Second)}
	}
	a.keyEvents[key] = append(k, now)
	a.nameEvents[p.Name] = append(n, now)
	return nil
}
func (a *Admitter) reserve(p *registration.Body, now int64) *Error {
	for pair, expiry := range a.nonces {
		if now >= expiry {
			delete(a.nonces, pair)
		}
	}
	pair := nonceID{key: p.Key.Encoding()}
	copy(pair.nonce[:], p.Nonce)
	if _, exists := a.nonces[pair]; exists {
		return deny(refusal.NonceReplayed)
	}
	a.nonces[pair] = p.ExpiresAt + 30
	return nil
}
func (a *Admitter) final(p *registration.Body, m *metadata, generation uint64) (Reading, *Error) {
	r := a.observe()
	if err := a.authority(p, r, m); err != nil {
		return r, err
	}
	if a.auditFenced {
		return r, deny(refusal.AuditUnavailable)
	}
	if a.signing.paused || a.signing.signer == nil || len(a.signing.public) != 32 || a.signing.generation != generation {
		return r, deny(refusal.ServiceUnavailable)
	}
	return r, nil
}

// Admit returns a JWT only after local durable audit, exact off-host ack and the
// final serialized rows 8–17/generation check. All later failures retain charges
// and nonce consumption. Sign/ack never run under the admission state mutex.
func (a *Admitter) Admit(parent context.Context, request Request) (string, error) {
	ctx, cancel := a.bounded(parent)
	defer cancel()
	if request.Proof == nil || request.Proof.Key == nil || len(request.Proof.Nonce) != 16 {
		return "", a.refuse(ctx, deny(refusal.RegistrationMalformed), metadata{bytes: capped(request.Bytes)})
	}
	p := *request.Proof
	p.Key = request.Proof.Key.Clone()
	p.Nonce = append([]byte(nil), request.Proof.Nonce...)
	m := proofMetadata(&p, request.Bytes)
	a.mu.Lock()
	r := a.observe()
	var failure *Error
	if a.auditFenced {
		failure = deny(refusal.AuditUnavailable)
	} else {
		failure = a.authority(&p, r, &m)
	}
	if failure == nil {
		failure = a.budget(&p, r.Monotonic)
	}
	if failure == nil {
		failure = a.reserve(&p, r.UTC)
	}
	generation := a.signing.generation
	if failure == nil {
		r, failure = a.final(&p, &m, generation)
	}
	slot := a.signing
	a.mu.Unlock()
	if failure != nil {
		return "", a.refuse(ctx, failure, m)
	}
	if ctx.Err() != nil {
		return "", a.refuse(ctx, deny(refusal.ServiceUnavailable), m)
	}
	input, prefix, err := jwtInput(&p, a.audience, r.UTC)
	if err != nil {
		return "", a.refuse(ctx, deny(refusal.ServiceUnavailable), m)
	}
	signature, err := slot.signer.Sign(ctx, append([]byte(nil), input...))
	if err != nil || ctx.Err() != nil || !ed25519.Verify(slot.public, input, signature) {
		return "", a.refuse(ctx, deny(refusal.ServiceUnavailable), m)
	}
	token := prefix + "." + base64.RawURLEncoding.EncodeToString(signature)
	a.mu.Lock()
	_, failure = a.final(&p, &m, generation)
	a.mu.Unlock()
	if failure != nil {
		return "", a.refuse(ctx, failure, m)
	}
	if err = a.record(ctx, m, "issued", nil, r.UTC, true); err != nil {
		return "", a.refuse(ctx, deny(refusal.AuditUnavailable), m)
	}
	a.mu.Lock()
	_, failure = a.final(&p, &m, generation)
	if failure == nil && ctx.Err() != nil {
		failure = deny(refusal.ServiceUnavailable)
	}
	if failure != nil {
		a.mu.Unlock()
		return "", a.refuse(ctx, failure, m)
	}
	// Linearization point for release; publication and cutover use the same mutex.
	a.mu.Unlock()
	return token, nil
}

// Refuse audits checks 1–7/routing failures supplied by the caller. Identity is
// deliberately null because this entrypoint accepts no verified identity data.
// The code must be one of the fixed protocol codes, never request/exception text.
func (a *Admitter) Refuse(parent context.Context, code refusal.Code, observedBytes uint64) error {
	ctx, cancel := a.bounded(parent)
	defer cancel()
	if status(code) == 0 {
		code = refusal.ServiceUnavailable
	}
	return a.refuse(ctx, deny(code), metadata{bytes: capped(observedBytes)})
}

// RecoverAudit reopens only the local recording fence after a bounded sink probe
// confirms its exact durable chain tip. It never clears a clock fence or cache.
func (a *Admitter) RecoverAudit(parent context.Context) error {
	ctx, cancel := a.bounded(parent)
	defer cancel()
	if err := a.acquireAudit(ctx); err != nil {
		return deny(refusal.AuditUnavailable)
	}
	defer a.releaseAudit()
	if err := a.sink.Probe(ctx, a.head); err != nil || ctx.Err() != nil {
		return deny(refusal.AuditUnavailable)
	}
	a.mu.Lock()
	a.auditFenced = false
	a.mu.Unlock()
	return nil
}
