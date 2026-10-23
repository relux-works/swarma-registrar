// Package ccj implements specification §2 CCJ-1.
//
// Callers select the format refusal code and supply byte slices or supported JSON values.
// The implementation stays internal. Registration-proof verification remains
// internal and is not provided by these public format packages.
//
// This package performs no I/O or network access and has no mutable global or
// process state. Caller-supplied interfaces own external operations; configured
// objects and immutable snapshots hold only their own instance data.
//
// Stability: any public API or loader behavior change requires its own reviewed
// pull request. Consumers pin a reviewed commit that has landed on main and raise
// that pin in their own reviewed change. api.txt and the API-surface test guard
// exported names, fields and methods only. An unchanged api.txt or green inventory
// test is not approval for a signature or behavior change.
package ccj
