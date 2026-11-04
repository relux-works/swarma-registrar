package adapters

import (
	"context"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-registrar/internal/adapters/matrixaudit"
)

// OpenAudit selects the configured profile. Credentials are read once here,
// before the session/worker exists. A disabled profile has no release authority.
func OpenAudit(ctx context.Context, c Config) (*Audit, error) {
	a, err := NewAudit(ctx, c.AuditFile, nil, c.ObjectFormat)
	if err != nil {
		return nil, err
	}
	if c.AuditHomeserver == "" {
		return a, nil
	}
	token, err := loadAuditToken(c.AuditToken, privateFile)
	if err == nil {
		err = a.ConnectMatrix(ctx, matrixaudit.Config{Origin: c.AuditHomeserver, Room: c.AuditRoom, User: c.AuditUser, BindingPath: filepath.Join(filepath.Dir(c.AuditFile), "audit-binding")}, token)
	}
	if err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// ConnectMatrix accepts already validated profile values and once-loaded token
// bytes. Call once during startup, before publishing this Audit to any caller.
func (a *Audit) ConnectMatrix(ctx context.Context, cfg matrixaudit.Config, token []byte) error {
	if a.matrix != nil || a.remote != nil {
		return failure(configurationInvalid)
	}
	session, err := matrixaudit.StartSession(ctx, cfg, token, a.snapshot)
	if err != nil {
		return err
	}
	a.matrix = session
	worker, cancel := context.WithCancel(ctx)
	a.stopDelivery = cancel
	a.deliveryDone = make(chan struct{})
	go func() { defer close(a.deliveryDone); session.Run(worker) }()
	return nil
}

func (a *Audit) snapshot(ctx context.Context) ([][]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.bad {
		return nil, failure(auditUnavailable)
	}
	h, size, err := a.scan(ctx)
	if err != nil || h != a.head || size != a.size {
		a.bad = true
		return nil, failure(auditUnavailable)
	}
	lines := [][]byte{}
	for offset := int64(0); offset < size; {
		if ctx.Err() != nil {
			return nil, failure(auditUnavailable)
		}
		line, err := a.lineAt(offset, size)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
		offset += int64(len(line))
	}
	return lines, nil
}

// BeginIssue is the row-21 precheck/reservation. No local/admission mutex spans
// it. Refusals can still append locally while a delivery is blocked off-host.
func (a *Audit) BeginIssue(ctx context.Context) (context.Context, func(), error) {
	if a.matrix == nil {
		if a.remote == nil {
			return ctx, nil, failure(auditUnavailable)
		}
		return ctx, func() {}, nil // Alternate qualified Remote contract.
	}
	return a.matrix.Begin(ctx)
}
func (a *Audit) stopMatrix() error {
	if a.matrix == nil {
		return nil
	}
	a.stopDelivery()
	select {
	case <-a.deliveryDone:
	case <-time.After(5 * time.Second):
		return failure(auditUnavailable)
	}
	return a.matrix.Close()
}

// DeliveryReady is an observation only; BeginIssue always checks again.
func (a *Audit) DeliveryReady() bool {
	if a.matrix != nil {
		return a.matrix.Ready()
	}
	return a.remote != nil
}
