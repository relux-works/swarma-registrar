package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/internal/ccj"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	"github.com/relux-works/swarma-registrar/internal/registration"
)

type metadata struct {
	jti, key, host, name, revision *string
	bytes                          int64
}

func capped(count uint64) int64 {
	if count > 65537 {
		return 65537
	}
	return int64(count)
}
func zeroHash() string { return strings.Repeat("0", 64) }
func validHead(h AuditHead) bool {
	if h.Sequence < 0 || h.Sequence > ccj.MaxInteger || len(h.Hash) != 64 {
		return false
	}
	for _, c := range h.Hash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return h.Sequence != 0 || h.Hash == zeroHash()
}
func hashLine(line []byte) string { sum := sha256.Sum256(line); return hex.EncodeToString(sum[:]) }
func proofMetadata(p *registration.Body, count uint64) metadata {
	key := hashLine([]byte(p.Key.Encoding()))
	key = "sha256:" + key
	id := p.ID
	return metadata{jti: &id, key: &key, bytes: capped(count)}
}
func nullable(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
func status(code refusal.Code) int64 {
	switch code {
	case refusal.RegistryUnavailable, refusal.ServiceUnavailable, refusal.AuditUnavailable:
		return 503
	case refusal.KeyNotEnrolled, refusal.KeyNotValidNow, refusal.HostRevoked, refusal.NameNotPermitted, refusal.AudienceMismatch, refusal.RegistrationSignatureInvalid, refusal.SignatureHighS, refusal.RequestNotYetValid, refusal.RequestExpired:
		return 403
	case refusal.NonceReplayed:
		return 409
	case refusal.RateLimited:
		return 429
	case refusal.RegistrationMalformed, refusal.RegistrationIDMismatch, refusal.NameInvalid, refusal.ClockSkew:
		return 400
	case "endpoint_not_found":
		return 404
	case "method_not_allowed":
		return 405
	case refusal.RequestTooLarge:
		return 413
	case "unsupported_media_type":
		return 415
	}
	return 0
}
func (a *Admitter) refuse(ctx context.Context, failure *Error, m metadata) error {
	if err := a.record(ctx, m, "refused", failure, 0, false); err != nil {
		if ctx.Err() != nil {
			// §9 still requires a local refusal after an expired issuance/ack.
			// Fence before returning; a separate bounded spool attempt must not
			// extend the response deadline or implicitly reopen admission.
			cleanup, cancel := a.bounded(context.Background())
			a.life.child()
			go func() {
				defer cancel()
				_, err := a.appendLocal(cleanup, m, "refused", deny(refusal.AuditUnavailable), 0)
				a.life.finish(err != nil || cleanup.Err() != nil)
			}()
		}
		return deny(refusal.AuditUnavailable)
	}
	return failure
}

// Cancellation bounds acquisition itself, including when another request owns
// the sequencer. Recheck after selection so an already-cancelled context cannot
// acquire an available slot and start an append or recovery probe.
func (a *Admitter) acquireAudit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case a.auditGate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			a.releaseAudit()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *Admitter) releaseAudit() { <-a.auditGate }

func (a *Admitter) record(ctx context.Context, m metadata, outcome string, failure *Error, jwtIat int64, requireAck bool) error {
	line, err := a.appendLocal(ctx, m, outcome, failure, jwtIat)
	if err != nil {
		return err
	}
	// No admission or chain-state lock may be held across off-host I/O (§6.1).
	err = a.sink.Acknowledge(ctx, append([]byte(nil), line...))
	if requireAck && (err != nil || ctx.Err() != nil) {
		return deny(refusal.AuditUnavailable)
	}
	// Refusals may remain durably spooled locally when off-host ack is unavailable.
	return nil
}

// appendLocal owns only local chain sequencing. Detached deadline cleanup uses
// this path without remote acknowledgement; its context has its own finite budget.
func (a *Admitter) appendLocal(ctx context.Context, m metadata, outcome string, failure *Error, jwtIat int64) ([]byte, error) {
	if err := a.acquireAudit(ctx); err != nil {
		a.fenceAudit()
		return nil, deny(refusal.AuditUnavailable)
	}
	defer a.releaseAudit()
	a.mu.Lock()
	r := a.observe()
	a.mu.Unlock()
	if !validUTC(r.UTC) || ctx.Err() != nil {
		a.fenceAudit()
		return nil, deny(refusal.AuditUnavailable)
	}
	code := "issued"
	http := int64(200)
	var iat, exp any
	if failure != nil {
		code = string(failure.Code)
		http = status(failure.Code)
	} else {
		iat = jwtIat
		exp = jwtIat + 120
	}
	event := map[string]any{"v": int64(1), "seq": a.head.Sequence + 1, "at": time.Unix(r.UTC, 0).UTC().Format("2006-01-02T15:04:05Z"), "instance": a.instance, "jti": nullable(m.jti), "key_id": nullable(m.key), "host": nullable(m.host), "name": nullable(m.name), "outcome": outcome, "code": code, "http_status": http, "registry_revision": nullable(m.revision), "jwt_iat": iat, "jwt_exp": exp, "request_bytes": m.bytes, "prev_hash": a.head.Hash}
	line, err := ccj.Marshal(event, refusal.AuditUnavailable)
	if err == nil {
		line = append(line, '\n')
		err = a.sink.Append(ctx, append([]byte(nil), line...))
	}
	if err != nil {
		a.fenceAudit()
		return nil, deny(refusal.AuditUnavailable)
	}
	a.head = AuditHead{Sequence: a.head.Sequence + 1, Hash: hashLine(line)}
	return line, nil
}
func (a *Admitter) fenceAudit() { a.mu.Lock(); a.auditFenced = true; a.mu.Unlock() }
