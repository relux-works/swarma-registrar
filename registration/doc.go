// Package registration builds and self-checks registration/1 proofs using
// specification §§2.1–3.2 (CCJ-1, envelopes and signatures), §5 (names) and §6.1
// rows 5–7. Its implementation and cryptographic validators remain internal.
//
// The caller supplies an exact encoded public key, name, audience, independently
// generated 16-byte nonce and exact whole-second UTC timestamps in Body. Build
// applies Check and returns canonical body bytes and the domain-separated signing
// preimage. Sign that preimage outside this package: ordinary Ed25519 over the
// bytes, or P-256 ECDSA over SHA-256(preimage), with raw 32-byte r || 32-byte s
// and low S. Assemble encodes the raw signature; Verify must succeed before release.
// Do not modify the body between Build and Assemble.
//
// Check and Build require the trusted, validated canonical configured audience
// for the mxid byte cap. They do not compare it with Body.Audience. Check performs
// schema and name checks without enrollment. Key-point validity remains deferred
// to Verify, exactly as in the registrar. Verify checks rows 5–7 in order and does
// not run the later name, enrollment, audience-equality, time, replay, rate or audit
// checks. Its returned Body is data, not authority or an admission decision.
//
// This package performs no HTTP, network or filesystem operations, generates no
// nonces or keys, accepts no private keys and holds no mutable global or process
// state. It does not issue JWTs, select enrollment policy or read a clock.
//
// Stability: every later public API or behavior change requires its own reviewed
// pull request. Consumers pin a reviewed commit landed on main and raise that pin
// in their own reviewed change. api.txt and TestAPISurface inventory exported
// names, fields and methods; a green inventory does not approve semantic changes.
package registration
