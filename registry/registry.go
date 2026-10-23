package registry

import (
	"github.com/relux-works/swarma-registrar/internal/library"
	"github.com/relux-works/swarma-registrar/internal/refusal"
	core "github.com/relux-works/swarma-registrar/internal/registry"
)

// Entry is one complete Git path, byte payload and entry type.
type Entry = core.Entry

// EntryKind distinguishes regular files from refused enrollment entry types.
type EntryKind = core.EntryKind

// Input carries the complete candidate, retained evidence and explicit freshness decision.
type Input = core.Input

// Verifier binds complete entries to an approved signed commit and verifies ancestry.
type Verifier = core.Verifier

// Store atomically compares and durably commits high-water state before authority returns.
//
// If Store.Commit returns an error, the durable state is indeterminate. Load
// returns no snapshot and no replacement high-water. The caller MUST fence
// admission and MUST NOT continue with either the previous or the new state.
// On the next start, the stored high-water MUST be treated as unreconciled until
// an operator reconciles it. This follows spec §4.4: persistence failure is
// registry_unavailable and fences admission; restored or missing rollback
// evidence fences admission until reconciled.
type Store = core.Store

// HostWater retains a host's highest position, tombstone and immutable historical IDs.
type HostWater = core.HostWater

// HighWater retains the approved revision, historical IDs and permanent ownership attribution.
type HighWater = core.HighWater

// Loader validates with caller-supplied Policy, Verifier and Store.
type Loader = library.Loader

// Snapshot provides read-only current records, exact key lookup and name authorization.
type Snapshot = library.Snapshot

// Diagnostic carries a typed refusal code and restricted operator Git-path context.
// Error() emits only the code; do not expose Path as a remote error detail.
type Diagnostic = core.Diagnostic

// Code is a stable specification refusal code.
type Code = refusal.Code

// Error is the underlying stable refusal available through errors.As, including diagnostics.
type Error = refusal.Error

// Limits and entry types are the snapshot prerequisites in spec §4.4.
const (
	MaxEntries = core.MaxEntries
	MaxBytes   = core.MaxBytes
	Regular    = core.Regular
	Symlink    = core.Symlink
	Other      = core.Other
)

// Loader and snapshot authorization refusal codes.
const (
	EnrollmentMalformed        = refusal.EnrollmentMalformed
	EnrollmentSigsUnsupported  = refusal.EnrollmentSigsUnsupported
	EnrollmentIDMismatch       = refusal.EnrollmentIDMismatch
	EnrollmentSignatureInvalid = refusal.EnrollmentSignatureInvalid
	RegistryUnavailable        = refusal.RegistryUnavailable
	RegistryConflict           = refusal.RegistryConflict
	RegistryRollback           = refusal.RegistryRollback
	NameInvalid                = refusal.NameInvalid
	NameNotPermitted           = refusal.NameNotPermitted
	HostRevoked                = refusal.HostRevoked
)
