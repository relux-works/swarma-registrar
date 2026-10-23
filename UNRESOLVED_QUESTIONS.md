# Open questions

Settled decisions and remaining activation dependencies are in
[the decision appendix](spec/registrar.md#appendix-c-decisions-open-questions-and-source-gap-choices-informative).

P2, P3 and P5 are settled: station hosts require UID maps, group-only admission
has no legacy mode, phase 0 trusts the pinned verified signed-commit registry,
reserved `sigs` is refused, and registry placement is deployment-owned.
E1 is approved: the owner holds one offline Ed25519 enrollment-publisher key;
root-owned, non-agent-writable configuration supplies the out-of-band publisher
public pin, maintainer allowlist and approved revision. Registrar and Keymaker
verify commit and envelope with the same pins and rule. HS3 accepts stock
60-second JWT leeway, with revocation accounting for `exp + 60`. The
86,400-second access-token target without refresh-token issuance is accepted.
HS1 records the source-confirmed `algorithm="EdDSA"` configuration correction.

KM1 is bound: the Keymaker reference in §1 uses landed main head
`f5bbba2281c224c2c120cc422644cc8a1fda1bf8`; the cited helper, peer-UID and enrollment
contracts have been checked.

Remaining dependencies:

- Service activation: production clock health/startup-ordering evidence and an authenticated durable off-host audit sink still need implementations and qualification. The binary supplies neither; it stays clock-fenced and never releases a JWT without remote acknowledgement. Interactive registry reconciliation alone cannot qualify them.
- HS2 / HS4: the chosen reviewed change to the operated homeserver must provide access-token expiry without refresh-token issuance and refuse JWT login for deactivated accounts. Deployment remains blocked until that change is qualified. Specification, vectors and service code continue meanwhile; §11's lock/containment and logout steps remain required.

These are implementation and qualification dependencies, not unresolved choices
of signer, leeway, token lifetime or homeserver-fix path. This file records no
passing deployment qualification.

## Media-type decisions

Content review on 2026-10-23 settled both questions. Section 6 permits SP/HTAB
around the complete field value and the charset-separating semicolon, forbids
whitespace inside tokens or around `=`, and requires an unquoted charset value.
Quoted charset values of any case yield `unsupported_media_type`; this is a
deliberate narrowing of RFC 9110's quoted parameter syntax. These choices are
no longer open. HTTP implementation alignment is a separate pending change.

## External high-water witness proposal

The 2026-10-23 content-review ruling requested option C: record every accepted
high-water digest outside the host's failure domain and compare local state
with the fresh latest witnessed state on start. Specification §4.5 and Appendix
B.2 are a proposal for independent review and content review before any code.
They do not claim implemented or qualified witness support. Option A remains
explicit operator reconciliation on every start or after indeterminate
persistence; a local file or cached acknowledgement alone is insufficient.

Open choices and recommendations are tracked in Appendix C.3:

- **WC1 — Witness and independent retention:** recommend an independently
  administered append-only service and separately retained trusted checkpoint.
  Qualify rollback/restore boundaries; matching stale host and witness views
  cannot establish freshness without independent surviving evidence.
- **WC2 — Authenticated fresh-head protocol:** recommend extending the §9 audit
  channel with typed witness append/read operations, protected peer pins and
  challenge-bound linearizable latest-head replies. Exact framing, nonce
  strength, credentials/rotation, record limits and continuity proofs remain
  open. Ordinary shipping or signed historical records do not suffice.
- **WC3 — Second consumer:** recommend separate consumer-bound streams on the
  same external service with common registry/pin policy. Shared streams need
  serialized ownership and lagging-reader fences. Keymaker internals remain
  owned by its separate specification.
- **WC4 — Instance takeover:** recommend explicit exclusion of the old serving
  instance before replacement and throughout authority use. A witness write CAS
  does not prevent an old process from signing. Any distributed lease needs a
  separately reviewed signing-fence design.
- **WC5 — Reconciliation and recovery runbook:** recommend operator actions
  bound to the exact digest/revision and independent surviving evidence for
  bootstrap, manual fallback, witness repair/migration and mode changes. Define
  operator authorization/evidence records and the no-surviving-evidence
  procedure. The proposed mechanism is now an exact externally durable intent
  acknowledged before Store.Commit, followed by a matching committed resolution
  after successful local commit. Local pending metadata is insufficient across
  whole-host restore. A latest unresolved intent fences regardless of local
  digest or remembered pending state. Operator completion must bind the intent
  hash, candidate digest/revision and independent evidence; no automatic
  roll-forward or rollback from local bytes is permitted. Any intent cancellation
  or replacement procedure remains a separate open decision.

Option C activation is blocked until these choices and their qualification
evidence are supplied. This does not block specification review. No automatic
downgrade, empty-stream bootstrap or joint-rollback detection is claimed.
