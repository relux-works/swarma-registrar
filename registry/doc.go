// Package registry implements specification §§4.3–4.4 snapshot validation and §5 name authorization.
//
// Callers supply complete in-memory entries, protected pin provenance, reconciled rollback evidence, signed-commit/ancestry Verifier and durable atomic CAS Store. Failed reloads require callers to fence admission.
// The implementation stays internal. Registration-proof verification remains
// internal and is not provided by these public format packages.
//
// This package performs no I/O or network access and has no mutable global or
// process state. Caller-supplied interfaces own external operations; configured
// objects and immutable snapshots hold only their own instance data.
//
// Stability: any public API or loader behavior change requires its own reviewed
// pull request. Consumers raise their dependency pin with an explicit commit.
// api.txt and the API-surface test guard exported names, fields and methods.
package registry
