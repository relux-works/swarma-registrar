# Carrier admission specification

Status: draft for content review. Sections 1–11 are normative unless marked
informative. Appendices declare their status individually. MUST, MUST NOT,
SHOULD and MAY express requirement levels. This draft publishes contracts,
not an implemented or qualified service.

## 1. Scope and authority (normative)

The registrar admits an enrolled host's permitted Matrix localpart. It proves
possession of a host key, not the correctness of an agent or its authorization
to perform work. Humans use a separate identity-provider login path.

| Component | Responsibility and trust boundary |
| --- | --- |
| Registrar | Owns `registration/1`, `enrollment/1`, their envelopes, name and `uid_map` semantics, registry validation, HTTPS admission, JWT issuance and audit. Its only private key is its JWT signing key. |
| Keymaker | Separate host-helper module. Owns host-key custody, kernel peer-UID checks, helper socket framing, negotiation, operations and refusal codes. |
| Homeserver | Trusts the registrar public key; validates login JWTs and creates local accounts. It never trusts host keys directly. |
| a2a CLI | Carries helper proof to registrar and login JWT to homeserver. Holds its resulting access token, never the host or registrar private key. |
| Enrollment publisher | Offline authority that signs records; registry maintainers publish them through reviewed, signed commits. |

The helper interface belongs to the [Keymaker specification,
`swarma-keymaker spec/keymaker.md` at `f5bbba2281c224c2c120cc422644cc8a1fda1bf8`](https://github.com/relux-works/swarma-keymaker/blob/f5bbba2281c224c2c120cc422644cc8a1fda1bf8/spec/keymaker.md), operations
`hello { versions: [1] }` and `sign_registration { name, aud }`. Keymaker uses
the framing convention in broker §13.1. This document MUST NOT be treated as a
second socket or helper-refusal specification. Its `uid_map` format is the data
contract Keymaker consumes. The reference is bound to the landed
`swarma-keymaker` main head cited above (decision KM1).

A station has its own OS account, carrier identity and keys. The registrar
cannot observe a remote caller's UID; only Keymaker enforces that boundary.
Group-only helper admission is removed entirely, with no legacy flag
(decision P2). A nonstation enrollment without `uid_map` authorizes no helper
caller; caller authorization requires an explicit UID map.

### 1.1 References and end state (informative)

The design reference is [CIP-0019](https://github.com/relux-works/curator-spec/blob/main/cips/CIP-0019-carrier-admission-by-public-key.md).
Canonicalization comes from [registry protocol §1](https://github.com/relux-works/curator-spec/blob/main/protocol/registry.md)
and [Decision 0002](https://github.com/relux-works/curator-spec/blob/main/decisions/0002-canonical-json-and-registry-trust.md).
Envelope and refusal conventions follow [broker §6.1, §6.4, §13.1 and Appendix A](https://github.com/relux-works/swarma-credential-broker/blob/main/spec/broker.md).
Station isolation follows the [CIP-0024 draft](https://github.com/relux-works/curator-spec/blob/cip/agent-stations-261022/cips/CIP-0024-agent-stations.md).
These are format/design references; the public-key and base64 formats of other
registry objects do not override the envelope specified here.

A future bridge appservice owns the carrier namespace and agent accounts cease
to be the admission unit. The reusable core remains proof → enrollment → short
carrier credential. The target enrollment design is a signature on each record
made by the owner on the owner's device. Phase 0 authenticates the registry revision through a
verified signed commit; it does not claim that commit signing is a device-held
owner act. Keymaker-derived identities and owner-root chains require
a later version; no chain-verification support is implied by this draft.

## 2. Bytes, canonicalization and envelope (normative)

### 2.1 JSON and CCJ-1 (normative)

Inputs MUST be UTF-8 JSON without a BOM. A parser MUST retain integer precision
and reject duplicate member names at every depth (including escaped aliases),
invalid UTF-8, lone surrogates, non-integer numeric tokens (including `1.0` and
`1e0`), negative zero, and integers outside
`[-9007199254740991, 9007199254740991]`. Unknown members, missing required
members and wrong JSON types MUST be rejected, including nested members.
Nesting depth MUST NOT exceed 16 (the root object is depth 1).

CCJ-1 recursively sorts object member names by Unicode scalar value, preserves
array order, emits no insignificant whitespace, and encodes strings as UTF-8.
It escapes only quote, backslash, `\b`, `\f`, `\n`, `\r`, `\t`, and remaining
U+0000–U+001F as lowercase `\u00xx`. It MUST NOT escape `/`, `<`, `>`, `&` or
non-ASCII characters. Integers use shortest base-10 spelling, zero is `0`, and
literals are `true`, `false`, `null`. Unicode normalization MUST NOT be applied.
A valid surrogate pair decodes to its scalar before canonicalization.

The registry protocol's top-level `sig` removal is an envelope extraction rule.
Here the signed input is **only `body`**, which has no `sig` member. A verifier
MUST NOT recursively strip members named `sig`, or sign/hash the full envelope.
Incoming JSON need not already have canonical whitespace, key order or escapes;
accepted semantic values MUST yield the canonical preimage. Noncanonical
base64url spellings remain invalid even in otherwise valid JSON.

For registration, all parsing/schema/CCJ-1 failures map to
`registration_malformed`, except the name, key and signature semantic checks
explicitly deferred in §6. For enrollment the equivalent failures map to
`enrollment_malformed`. Serializer conformance cases in Appendix B exercise
canonicalization independently even when a string is not legal in a body field.

### 2.2 Encodings and signed envelope (normative)

An envelope MUST have exactly `body`, `id`, `sig`. `body` MUST be an object.
`id` MUST match `^sha256:[0-9a-f]{64}$` (71 ASCII bytes).
`sig` MUST be canonical unpadded base64url of exactly 64 decoded bytes
(86 characters). All base64url here uses `A–Z a–z 0–9 - _`, no `=`, no
whitespace, and zero unused trailing bits: decode then re-encode MUST give the
same string. Standard base64 `+` and `/` MUST be rejected.

For body type `registration/1`, domain is ASCII
`swarma-registrar registration/1`; for `enrollment/1`, it is ASCII
`swarma-registrar enrollment/1`. Define:

```text
preimage = ASCII(domain) || 0x0a || CCJ-1(body)
id       = "sha256:" || lowercase_hex(SHA-256(preimage))
sig      = base64url_no_pad(signature(preimage))
```

There is no trailing newline in the preimage. Neither `id` nor `sig` enters
it. A well-formed but unequal id yields `registration_id_mismatch` or
`enrollment_id_mismatch`. Wrong domains fail signature verification if the id
has been recomputed for the required domain; otherwise id mismatch wins.

One HTTP request body MUST be at most 65,536 bytes, measured on received bytes.
One enrollment envelope file has the same limit. Readers MUST enforce limits
while streaming, including absent/dishonest lengths. Registration oversize is
`request_too_large`; enrollment oversize is `enrollment_malformed`.

## 3. Registration body and cryptography (normative)

The body MUST contain exactly these seven members:

| Member | Type and constraints |
| --- | --- |
| `type` | String, exactly `registration/1`. |
| `key` | String, exactly one of the public-key encodings below; at most 128 ASCII bytes. |
| `name` | String; localpart syntax, server-dependent byte limit and authorization in §5. Maximum wire length 255 UTF-8 bytes before semantic validation. |
| `aud` | String, 1–255 ASCII bytes; exact configured Matrix server name, never a URL, origin or homeserver API address. Wrong value is `audience_mismatch`. |
| `nonce` | String, canonical unpadded base64url of exactly 16 bytes (22 characters), generated independently with a CSPRNG for each attempt. |
| `iat` | String, timestamp below. |
| `exp` | String, timestamp below, strictly after `iat`, with `exp - iat <= 120` seconds. |

A timestamp MUST be exactly `YYYY-MM-DDTHH:MM:SSZ` (20 ASCII bytes), a valid
Gregorian date in years 1970–9999. Hours are 00–23; minutes and seconds are
00–59. Leap seconds, fractions, timezone offsets, lowercase `t`/`z`, missing
zero-padding and nonexistent dates MUST be rejected as malformed. All durations
are differences of Unix seconds. `exp <= iat` and a lifetime of 121 seconds
are malformed. The request MAY have a lifetime shorter than 120 seconds.

### 3.1 Public keys (normative)

`ed25519:` MUST be followed by 32 decoded bytes (43 base64url characters,
51 total). The bytes MUST encode a canonical Ed25519 curve point in the
prime-order subgroup, excluding the identity. Noncanonical points, small-order
points and mixed-order points MUST be rejected. Signature `R` MUST likewise be
a canonical prime-order nonidentity point; `S` MUST satisfy `0 <= S < L`,
where `L = 2^252 + 27742317777372353535851937790883648493`. Verify the ordinary
Ed25519 equation over the preimage, without prehash or context mode. A
noncanonical `S`, weak key or invalid equation yields
`registration_signature_invalid`. These strict checks are also required for
enrollment signatures (`enrollment_signature_invalid`).

`p256:` MUST be followed by a 33-byte SEC1 compressed point (44 characters,
49 total). The first byte MUST be `02` or `03`. The remaining bytes are the
big-endian x coordinate, strictly below the P-256 field prime. Decompression
MUST yield an on-curve, nonidentity point of the stated parity. Uncompressed
points and invalid x coordinates MUST be refused. P-256's cofactor is one.
The prefix selects the algorithm; implementations MUST NOT infer an algorithm
from byte length, try the other algorithm, or coerce Ed25519 bytes into a point.
An Ed25519 key relabeled `p256:` therefore yields
`registration_signature_invalid` (enrollment: `enrollment_malformed`).

An unrecognized key prefix or bad base64url is malformed. A recognized prefix
with a wrong decoded key length or an invalid point reaches the signature check
and yields `registration_signature_invalid`. Enrollment validates keys as data
and maps those failures to `enrollment_malformed`.

### 3.2 P-256 signatures (normative)

P-256 signs `SHA-256(preimage)` with ECDSA. The signature MUST be exactly
`r || s`, each an unsigned 32-byte big-endian scalar; DER is not accepted as an
encoding. A 64-byte value is always interpreted as raw scalars, even if it is
also DER-shaped; no DER auto-detection changes its range/low-S/equation checks.
Let `n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.
Both scalars MUST satisfy `1 <= scalar < n`. Invalid ranges yield
`registration_signature_invalid`. After range checks, `s > floor(n/2)` yields
`signature_high_s`, before checking the ECDSA equation. Verification MUST NOT
normalize high-S input into an accepted signature. Key decoding precedes this
check. Any remaining equation failure yields `registration_signature_invalid`.
Ed25519 signatures are 64 raw bytes and have no `signature_high_s` outcome.

## 4. Enrollment and registry (normative)

### 4.1 Body schema (normative)

An enrollment body MUST contain exactly `type`, `host`, `keys`, `names`, `seq`,
`state`, and optionally `uid_map`. `sigs` is reserved: its presence, even `[]`
or `null`, MUST yield `enrollment_sigs_unsupported` after basic CCJ-1 parsing
and before the rest of the body schema. Unknown members are malformed.

| Member | Contract |
| --- | --- |
| `type` | Exactly `enrollment/1`. |
| `host` | ASCII string matching `^[a-z0-9-]{1,32}$`; no underscore. |
| `keys` | Array of 1–16 distinct public keys, each object exactly `{key, not_before, not_after}`. Algorithms and syntax are §3.1; both times are §3 timestamps. |
| `names` | Object exactly `{prefix, explicit}`. `prefix` MUST equal `host + "_"`. `explicit` is an array of 0–256 distinct localparts satisfying §5's legacy grammar and byte limit for the configured audience. |
| `uid_map` | Optional only for a host that runs no stations; otherwise REQUIRED (decision P2). Schema in §4.2. Every phase-0 registrar deployment MUST configure each loaded host label as station-bearing or nonstation independently of untrusted requests. Missing host classification fails registry loading. |
| `seq` | JSON integer in 1–9007199254740991; increases strictly for each host change. |
| `state` | Exactly `active` or `revoked`. A revoked body retains keys and names for attribution; revocation does not require a live host key. |

Each key's interval is `[not_before, not_after)`, with `not_before < not_after`.
At admission, both request `iat` and the registrar's current time MUST be inside
one interval for that exact key. No skew extends key authority. An instant
at the lower bound is valid; at the upper bound it is invalid. Request `exp`
need not fit the key window: an already issued credential has its own lifetime.
Distinct keys MAY overlap during rotation. Duplicate keys in one record MUST
be refused, even with disjoint windows. Arrays preserve their written order
for canonicalization; keys, explicit names and UID entries need no sorted order
and order never grants priority.

### 4.2 `uid_map` (normative)

`uid_map` MUST be an array of 1–256 objects. Each object has exactly `uid`,
`names`, and optionally `exe`:

- `uid`: JSON integer in 1–4294967294. UID 0, negatives, fractions, strings and
  the all-ones sentinel are forbidden.
- `names`: array of 1–64 distinct strings. Every string MUST be syntactically
  valid and permitted by that enrollment's `names` under §5. No glob, regex,
  prefix shorthand or empty name is allowed.
- `exe`: optional exact absolute POSIX path, 1–4096 UTF-8 bytes, starting `/`.
  Components MUST be nonempty and neither `.` nor `..`; no trailing slash,
  NUL, backslash or ASCII control character is allowed. `/` alone is invalid.
  The path is matched literally, without symlink resolution or normalization
  by the registrar. It is an additional narrowing condition at the helper,
  never a substitute for kernel UID evidence.

A UID MUST occur only once. Different UIDs MUST NOT claim the same name, to
preserve the station boundary. Multiple names for one UID support transitions;
separate stations MUST NOT share that UID. The registrar MUST validate all
these rules but MUST NOT claim to have enforced peer identity or executable
identity remotely. Helper behavior when executable identity cannot be proven
is owned by Keymaker; the check MUST NOT silently become UID-only there.
All `uid_map` schema/consistency failures yield `enrollment_malformed`.

### 4.3 Phase-0 signatures and pins (decisions P3, P5, E1) (normative)

The registry MUST be read from a configured local, non-agent-writable path at
an explicitly configured full Git commit object id. Registrar and Keymaker
MUST use the same configured revision, audience, pins and verification rule.
The pin configuration (registry-maintainer verification-key allowlist, approved
registry revision and enrollment-publisher public key) MUST be root-owned and
MUST NOT be writable by agent accounts. Both services MUST verify the signed
commit and the envelope signature with these same pins and the same rule.
Location and transport of that registry are deployment matters. Neither service
follows a mutable branch, fetches implicitly, or treats a working tree as authority.

The pinned commit MUST have a valid signature under an out-of-band configured
registry-maintainer verification-key allowlist, and MUST be the reviewed
protected-branch revision approved by the operator. A valid signature alone
does not prove review; the deployment pin is the operator's approval evidence.
Commit-author text, an embedded key and mere object existence are not trust.

Phase 0 MUST carry a real enrollment-envelope signature in `sig`, made with
one offline Ed25519 enrollment-publisher key (decision E1). The owner holds this
key offline. The publisher is a record-signing key class, separate from host
keys, JWT keys, broker roots and future phone/device keys. The verifier knows
exactly one current publisher public key in the §3.1 `ed25519:` encoding, pinned
out of band in the root-owned configuration above; there is no body-supplied
issuer or key-selection hint. No private publisher key resides at the registrar
or helper. Rotation of this pin requires the operator to re-sign the loaded
record history and advance the approved registry pin atomically while retaining
body/sequence/tombstone history. It MUST NOT reset rollback state. Publisher
rotation changes envelope signatures but not record ids.

The signed commit is the phase-0 enrollment authority; the envelope signature
is an additional integrity check, not self-enrollment. This settled phase-0
rule does not implement `sigs[]` or claim a presence-gated owner-device signature.

### 4.4 Snapshot selection and rollback (normative)

A registry revision contains `enrollments/*.json`, each file one envelope,
with history retained append-only. Other paths are not enrollment inputs.
The aggregate MUST contain at most 10,000 envelopes and 16 MiB of envelope
bytes. Symlinks and nonregular enrollment entries MUST be rejected. Filename
spelling carries no authority. Every envelope MUST validate before any new
snapshot is installed. Invalid records MUST NOT be skipped to choose a lower
`seq`.

Registry trust/readability, aggregate caps and entry-type prerequisites are
checked first; failure yields `registry_unavailable`. Then enumerate enrollment
files by unsigned-byte lexicographic order of their complete Git paths. Perform
**snapshot-wide phases** in the following order: complete one phase over every
file before starting the next. Within a phase, stop at the first failing file
in that path order. This traversal chooses diagnostic context, never authority.

| Phase | Check across all files / the complete snapshot | Diagnostic |
| --- | --- | --- |
| 1 | Per-file byte limit, CCJ-1 parsing and basic envelope shape. | `enrollment_malformed` |
| 2 | Presence of reserved body member `sigs`. | `enrollment_sigs_unsupported` |
| 3 | Remaining body, key, name and UID schema. | `enrollment_malformed` |
| 4 | Recomputed envelope id. | `enrollment_id_mismatch` |
| 5 | Publisher signature. | `enrollment_signature_invalid` |
| 6 | Duplicate positions, cross-host keys and explicit-name conflicts below. | `registry_conflict` |
| 7 | Revision ancestry, retained history/high-water and irreversible tombstones below. | `registry_rollback` |

Thus a reserved `sigs` in any well-shaped file wins over a bad publisher
signature in any other file, regardless of their path order. Conflict wins over
rollback when both exist. Only after all phases pass may atomic persistence and
installation occur; persistence failure is `registry_unavailable`. Every failure
refuses the entire candidate load atomically and fences admission. No earlier
file or valid lower sequence becomes partial authority.

Group records by exact host label. The highest valid `seq` is current; gaps
are allowed. Duplicate `(host, seq)` is `registry_conflict`, even for identical
bodies: there MUST be one record at each position. A host appearing at distinct
sequence positions is history, not a duplicate current host. A decoded public
key MUST NOT belong to different hosts anywhere in retained history, including
revoked hosts. An explicit legacy localpart MUST NOT be claimed by different
hosts anywhere in retained history, including revoked hosts and entries removed
from a current list. Removing a claim stops its current authorization but does
not release that name for another host. The same active host MAY remove and
later re-add its own legacy name at higher sequences. Moving a legacy name to
another host is outside this version. An explicit claim MUST NOT fall under
another host's structured namespace; either ambiguity is `registry_conflict`.
Prefix authorization of valid structured names otherwise belongs uniquely to
the parsed host.

A `revoked` record is an irreversible tombstone: a later `active` record for
that host is `registry_rollback`. Reusing a host label requires a new protocol
or an explicit future recovery design, not a sequence increment. An ordinary
host-key rotation does not revoke the host.

Services MUST durably retain the last accepted revision and each host's
highest `(seq, id)` plus revoked flag outside disposable caches. A replacement
pin MUST be the same revision or a Git descendant. It MUST retain every known
body/id and tombstone; lower seq, equal seq with different id, vanished host or
rewritten body history yields `registry_rollback`. Additional record signatures
from approved publisher rotation are allowed; historical bodies are immutable.
The new high-water state MUST be persisted atomically before new authority is
usable. An empty valid registry is permitted only at first bootstrap, never as
a fallback from an unreadable registry. A configured first-use pin bootstraps
trust explicitly; high-water loss is not first use.

Restored or missing rollback evidence MUST fence admission until the operator
reconciles it with trustworthy surviving evidence outside the restored failure
domain. A local sequence file cannot prove its own freshness after rollback.
The same rule applies at Keymaker. Section 4.5 defines an external-witness
alternative, with this operator reconciliation rule as fallback.
On any invalid/missing/unreadable registry,
unverifiable pin or failed reload, both services MUST stop new signing/issuance;
they MUST NOT continue using a possibly superseded snapshot. HTTP admission
returns `503 registry_unavailable`, with the loader diagnostic in restricted
operator logs. There is no network registry API in this version.

### 4.5 External high-water witness (option C; normative draft)

Option C replaces interactive reconciliation on every start (option A).
This proposal requires independent review and content review before
implementation. Registry validation, protected pins and the single-replica
rule remain required. A witness stores evidence, not enrollment authority.

#### 4.5.1 State digest and witness record

The digest MUST cover the complete retained §4.4 high-water. Its preimage MUST
be a CCJ-1 object with exactly `v` (integer 1) and `high_water` (object).
The latter MUST contain exactly these members:

| Member | Required value |
| --- | --- |
| `Revision` | The candidate's full lowercase Git commit id. |
| `Hosts` | Object keyed by exact host label. Each value has exactly `Seq`, `ID`, `Revoked` and `History`: highest positive safe-integer sequence, its body id, boolean tombstone flag, and complete sequence-to-body-id object. History keys are shortest positive decimal sequence strings; aliases such as `01` are forbidden. |
| `KeyOwners` | Complete retained canonical-public-key-string to host-label object, including historical ownership. |
| `NameOwners` | Complete retained explicit-name to host-label object, including removed claims. |

Maps MUST be objects, including empty maps; null or omitted maps are invalid.
History MUST include the highest `(Seq, ID)`. All §4.4 history, ownership and
tombstone invariants still apply. The digest MUST be `sha256:` followed by
lowercase SHA-256 hex of the complete canonical preimage bytes, without LF.
Filesystem metadata and witness receipts MUST NOT enter the preimage. These
are the current version-1 local-state field names; no adapter changes are
included in this proposal.

The witness MUST be outside the consumer's restore/failure domain. Protected
configuration MUST bind its authenticated identity and a stable stream to the
registry lineage and authorized consumer or consumer group. A restart or
restore MUST NOT select a new empty stream. A binding change requires option A
reconciliation; it MUST NOT erase retained history or tombstones.

A witness record MUST be one CCJ-1 object followed by LF, with exactly `v`
(integer 1), `stream` (a configured ASCII string matching
`[a-z0-9][a-z0-9._-]{0,127}`), `seq` (integer 1 through
9007199254740991), `kind` (`intent` or `committed`), `revision`, `digest`,
`prev_hash`, and `intent_hash`. Revision and digest MUST identify the exact
candidate high-water. `prev_hash` MUST be lowercase
SHA-256 hex of the previous complete witness line including LF, or 64 zeroes
at the first record. Sequence MUST increase by exactly one within the stream;
exhaustion MUST fence, not wrap or reset. Witness sequence is separate from
host `seq` and §9 admission-audit sequence.

An `intent` MUST have `intent_hash` null. Its `prev_hash` and sequence MUST bind
the exact expected previous resolved witness head. An empty stream requires
explicit option A bootstrap authorization before its first intent. There MUST
be room for both intent and resolution sequences before an intent is appended.
A `committed` record MUST immediately follow the unresolved intent, with the
same digest and revision. Its `intent_hash` and `prev_hash` MUST both equal the
SHA-256 of that complete intent line including LF. No new intent may bypass an
unresolved intent. A committed record resolves only that exact intent.

The witness MUST durably append before acknowledging. Its authenticated
acknowledgement MUST bind stream, sequence, revision, complete state digest and
SHA-256 of the exact complete record including LF. A prefix match, generic
success or receipt for another record MUST NOT acknowledge this commit.
Append MUST atomically compare the expected previous stream head. Conflicting
appends MUST fail closed. An exact retry MAY return the same receipt without a
second append; a different record at the same sequence MUST be rejected.
Acknowledged records MUST NOT be truncated, replaced or renumbered.

#### 4.5.2 Commit, start and fallback

The consumer MUST serialize registry replacement with new signing/issuance.
After all §4.4 validation passes, it MUST append the exact candidate's intent
and obtain its exact durable acknowledgement before calling `Store.Commit`.
It MUST then commit that exact high-water locally. Only after successful local
commit may it append the matching `committed` resolving record. It MUST obtain
that record's exact durable acknowledgement, revalidate local committed bytes
and the current approved pin, and only then use the new authority. This order
also applies to an unchanged-state commit. A cached earlier equal-digest record
MUST NOT replace either acknowledgement.

Admission MUST remain fenced throughout this replacement. Neither the old nor
the new snapshot may authorize signing/issuance before resolution. The durable
external intent, rather than host-local pending metadata, survives a whole-host
restore and records the outstanding obligation.

If the intent append or its acknowledgement fails, `Store.Commit` MUST NOT be
called. Local high-water is unchanged. The old authority MUST remain fenced:
this is a failed reload under §4.4, and a lost receipt may hide a durable intent.
Recovery MUST follow the fresh-head and reconciliation rules below; local bytes
alone MUST NOT clear this fence. Every witness failure yields
`registry_unavailable`, without a compensating local rollback.

If `Store.Commit` fails, local durability is indeterminate. The acknowledged
intent remains unresolved; no resolving append or authority use is permitted
until explicit option A recovery. If local commit succeeds but the resolving
append is not durable, the witness head remains the unresolved intent. The new
local high-water is retained and fenced, not reported as unchanged. If the
resolving append's outcome or acknowledgement is lost, the consumer MUST remain
fenced and treat resolution as unproven. A fresh authenticated latest-head reply
confirming that exact durable `committed` record MAY prove a lost resolution
receipt; it MUST bind all required acknowledgement fields. A newer/different
head MUST fence. An actual unresolved intent requires operator recovery below.
Validation failures still leave high-water unchanged as §4.4 requires.

On every start, option C MUST obtain a fresh authenticated read of the latest
durable record in the configured stream, including an intent whose append
receipt was lost. The witness MUST NOT return an older resolved record while
an unresolved intent is its head. It MUST answer from its
authoritative serialized head, not a stale replica, historical-record lookup or
client cache. The reply MUST bind a fresh unpredictable challenge from this
lookup. An old authenticated receipt alone is insufficient. Reads and appends
MUST share one consistent stream order. Every witness operation MUST have a
finite deadline, default five seconds; timeout MUST fence.

The consumer MUST validate local state, the witness record, stream binding,
sequence/chain continuity and fresh reply. It MUST recompute the local digest
and compare both digest and revision with the latest record. Only a latest
`committed` record resolving its exact intent, with digest and revision equal
to local state, permits reconciliation. All §4.4 pin, history and snapshot checks
still MUST pass. A latest unresolved `intent` MUST fence and require option A
operator recovery, whatever the local digest or locally remembered pending
state. This includes a whole-host restore that erased all local pending identity
after a changed-state or unchanged-state commit. Equality with an intent MUST
NOT reconcile. This read MUST NOT append or modify local high-water. The consumer
MUST reject a head below any trustworthy previously observed sequence, or a
different record at the same sequence. An advancing head requires append-only
continuity evidence from the prior head. A restored local sequence floor cannot
prove freshness; the witness's nonrollback/latest-head guarantee MUST survive
that restoration independently.

Unequal digest/revision, missing or invalid local state, an absent record,
unreachable/unauthenticated/stale witness, backwards sequence or broken chain
MUST leave the consumer fenced. A valid old record signature is not proof that
it is latest. An empty stream MUST NOT imply first use.

Option A applies when option C is not configured or any prerequisite above
cannot be established. On every start and after indeterminate persistence, the
operator MUST reconcile the exact local digest and retained history against
trustworthy surviving evidence outside the restored failure domain. Missing
state still requires explicit bootstrap or recovery authorization under §4.4.
Confirmation of the local file alone MUST NOT count as reconciliation.
While option C remains selected, operator confirmation MUST NOT bypass a pending
witness acknowledgement or overwrite a newer witness head. The operator MAY
explicitly select option A after evidence-based reconciliation; outage MUST NOT
silently downgrade the mode. Returning to option C requires an independently
reconciled stream binding and acknowledged current state. Repair of a rolled-
back witness requires surviving independent evidence, not acceptance of its
stale head. Without that evidence, both modes remain fenced.

To resolve an intent, the operator MUST first quiesce the consumer and exclude
older instances. The operator MUST obtain the fresh exact intent and independently
authenticate the candidate bytes/history and revision it commits to. Recovery
authorization MUST bind the complete intent hash, candidate digest, revision
and surviving external evidence. It MUST reconcile all §4.4 history, ownership
and tombstones; local restored bytes alone MUST NOT prove a commit did or did
not happen. With that authorization, the consumer MAY recover and durably commit
the exact intended candidate after full validation, or verify its independently
reconciled successful commit. It MUST then append and acknowledge the matching
`committed` record before final revalidation and use. This is an operator action,
not automatic roll-forward or rollback. The consumer MUST NOT cancel the intent,
substitute the pre-intent state or start a new stream on its own. If the exact
candidate cannot be independently recovered/approved, the intent remains
unresolved and option C remains fenced. An explicit switch to option A MUST
preserve this evidence; returning to C requires resolving the outstanding intent.
The operator runbook and any cancellation/replacement design remain open in WC5.

#### 4.5.3 Audit reuse, consumers and threat bounds

The registrar MUST reuse §9's authenticated off-host delivery channel and
durable exact-byte acknowledgement boundary for witness records. Witness lines
MUST occupy a separately typed and sequenced stream. They MUST NOT add fields
to §9's closed event schema or pretend to be `issued`/`refused` events. A §9
sink qualifies only if it also supplies the compare-head append and fresh
latest-head operations above. Ordinary audit shipping alone does not qualify.
Witness records MUST NOT contain private keys, tokens or enrollment bodies.
Witness intent, local commit and witness resolution are separate durability
steps, not a distributed atomic transaction. The acknowledged write-ahead intent
preserves the fence across host restoration between the latter steps.

A second registry consumer, including Keymaker, MUST apply the same commit,
freshness and fallback rule before using authority. It MUST use either a shared
witness stream with serialized updates or its own independent stream with the
same guarantees. A registrar receipt MUST NOT prove another consumer's state
without an exact local digest/revision comparison against a fresh latest head.
On observing a newer shared head, a lagging consumer MUST fence. This defines
no helper operations, refusal names or Keymaker internals.

There MUST be one active writer/serving instance per consumer. The deployment
MUST exclude an older instance for its entire authority-use lifetime before
replacement begins. Uncertainty MUST fence the replacement. Compare-head append
only arbitrates witness writes; it does not revoke an old instance's ability to
sign. Consumers sharing a stream additionally MUST serialize updates and
reconcile their own state before use. This is not a multi-replica design.

| Threat | Protection and limit |
| --- | --- |
| Restore local state and replay a stale witness view | At an honest witness, a fresh latest head is either the unresolved write-ahead intent (fence regardless of local state) or a resolved commit (compare digest/revision). A host restore cannot erase the external intent after either changed-state or unchanged-state commit. Restored local receipts/floors do not establish freshness. A compromised host bypassing checks, changing protected bindings or controlling the authenticated witness view is outside this claim. |
| Witness outage or partition | No automatic reconciliation or new authority release; explicit evidence-based option A recovery remains available. Availability is deliberately sacrificed. |
| Replay an old acknowledgement | Exact stream/sequence/record binding, compare-head append and challenge-bound latest reads prevent its use as proof of a newer commit or current startup state. Authentication alone does not prove latestness. |
| Roll back or equivocate at the witness | Observed regression, same-sequence change or broken continuity fences. An undetectably restored or malicious witness and host with no independent surviving head can agree on stale state; matching hashes alone cannot reveal that rollback. |
| Split brain | Single-instance exclusion and serialized compare-head writes are required. A witness is not a distributed signing lock; two active serving instances have no split-brain safety claim. |

Witness transport/authentication, independent retention and instance exclusion
need content-review choices and qualification in Appendix C.3. Until those
requirements are supplied, option C MUST NOT be activated.

## 5. Names and audiences (normative)

Structured localparts match this full grammar (ASCII, case-sensitive):

```text
host      = [a-z0-9-]{1,32}
project   = [a-z0-9][a-z0-9-]{0,31}
role      = [a-z0-9]{1,32}
qualifier = [a-z0-9]{1,16}
name      = host "_" project "_" role [ "-" qualifier ]
```

The CIP's `[-q]` is interpreted here as an optional qualifier, not a literal
letter `q`. The first underscore uniquely ends the host label. A structured
name is prefix-permitted only when that parsed label equals the enrollment
host AND the exact configured prefix matches. Prefix matching alone never
admits malformed structured names.

Legacy explicit localparts match `^[a-z0-9][a-z0-9._=\-]{0,254}$`. An
explicit entry is an exact entire string match, never a prefix or pattern.
A legacy name need not have a parseable host; its authority comes from the
enrolled signing key's host and the unambiguous explicit claim. A name that
satisfies the structured grammar is owned by its parsed host and MUST NOT be
borrowed by another host through an explicit entry. An explicit localpart can
be legacy even if it contains underscores but fails the structured grammar.

For either form, UTF-8 byte length of `"@" + name + ":" + aud` MUST be at most
255, so `len(name) <= 253 - len(aud)`. Empty names, uppercase, non-ASCII,
`@`, `:`, spaces, `/` and wildcards are forbidden. A syntactically invalid
request name yields `name_invalid`; a syntactically valid but unauthorized
name yields `name_not_permitted`. A well-formed legacy candidate absent from
the explicit list is the latter. No lowercasing, URL decoding or normalization
is performed by the registrar. Keymaker MUST validate before signing under its
own operation contract, using these shared name semantics.

The deployment MUST pin one canonical ASCII Matrix server name, validated as a
Matrix server-name value (hostname or IP literal, optionally a port), with no
scheme, path or trailing slash. It MUST fit the 255-byte mxid limit together
with every configured name. Requests compare `aud` to that configured string
byte for byte; even equivalent DNS case/port spellings are unequal. Name
length is evaluated against the configured audience before audience comparison,
so an attacker cannot alter the name verdict by sending a short audience.

## 6. Registrar HTTP API and refusal precedence (normative)

`POST /v1/registration` MUST run over HTTPS; plaintext MAY be used only in
isolated loopback tests. The body is the §2 registration envelope. The only
accepted media type is `application/json`, optionally `charset=utf-8`
(case-insensitive media/charset tokens); other parameters, multiple content-type
values and content encodings other than absent/`identity` are unsupported.
Optional whitespace (SP / HTAB) MAY surround the complete field value and the
`;` separating the charset parameter. Whitespace MUST NOT split type, subtype,
parameter-name or parameter-value tokens, or occur around `=`.
The charset value MUST be unquoted; quoted values, including any case of
`"utf-8"`, MUST yield `unsupported_media_type`. Refusing quoted values deliberately
narrows [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6),
which permits quoted parameter values.
Responses MUST have `Content-Type: application/json` and `Cache-Control: no-store`.

Success is `200 {"jwt":"<compact-JWS>"}` with exactly one member. Refusal is
an object exactly `{ "code": "<stable_code>", "message": "<safe summary>",
"details": {} }`, following the broker typed-error convention. `details` is
empty in v1; message text is not a machine contract. No JWT, bearer material,
raw request or private filesystem path may appear in a refusal. Wrong endpoint
and wrong method return `404 endpoint_not_found` and `405 method_not_allowed`
respectively; a 405 MUST carry `Allow: POST` for this path.

### 6.1 Ordered admission checks (normative)

The first failing row wins. Within a row all listed conditions have the same
code, except explicitly split substeps. Schema validation checks member types,
wire lengths and encoding lexemes first; it MUST defer validly encoded key
point/length checks, name grammar, authority and current-time checks to their
named rows. `sig` decoded length is an envelope shape check. Earlier rows
MUST NOT attempt later checks merely to select a different refusal.

| Order | Check / failed condition | Code | HTTP |
| --- | --- | --- | --- |
| 1 | Endpoint exists. | `endpoint_not_found` | 404 |
| 2 | Method is POST. | `method_not_allowed` | 405 |
| 3 | Received body fits byte cap; bound the stream before further interpretation. | `request_too_large` | 413 |
| 4 | Content type and content encoding supported. | `unsupported_media_type` | 415 |
| 5 | JSON, CCJ-1, envelope/body schema, timestamp syntax/duration, encodings. | `registration_malformed` | 400 |
| 6 | Recomputed id equals the supplied id. | `registration_id_mismatch` | 400 |
| 7a | Recognized key decodes to a point of the required size and strictness; P-256 scalars in range. | `registration_signature_invalid` | 403 |
| 7b | P-256 S is low. | `signature_high_s` | 403 |
| 7c | Strict signature equation verifies in the required domain. | `registration_signature_invalid` | 403 |
| 8 | A fully verified current registry snapshot is available. | `registry_unavailable` | 503 |
| 9 | Exact public key occurs in a current host record. History alone is insufficient. | `key_not_enrolled` | 403 |
| 10 | `iat` and current time are in that current key's half-open interval. | `key_not_valid_now` | 403 |
| 11 | Host state is active. | `host_revoked` | 403 |
| 12 | Name grammar and configured-audience mxid limit pass. | `name_invalid` | 400 |
| 13 | The key's host permits the name (§5). | `name_not_permitted` | 403 |
| 14 | Audience equals the configured server name. | `audience_mismatch` | 403 |
| 15 | Both startup provider checks and the 4-second monotonic hold passed before fixing process start; current provider evidence is healthy, unexpired and within delta_cap; no process-lifetime clock fence has tripped; `iat >= start_barrier = floor(fixed process-start UTC) + 31` (§7). | `clock_skew` | 400 |
| 16 | Request `iat <= now + 30`. | `request_not_yet_valid` | 403 |
| 17 | `now < request.exp + 30`. | `request_expired` | 403 |
| 18 | Both per-key and per-name budgets have capacity (§7). | `rate_limited` | 429 |
| 19 | `(key, nonce)` has not been consumed. Reserve it atomically. | `nonce_replayed` | 409 |
| 20 | Signer and service prerequisites work; all final authority/time checks still pass; signing-key generation remains current through release. | `service_unavailable` | 503 |
| 21 | Audit commit and off-host acknowledgement succeed before releasing JWT (§9). | `audit_unavailable` | 503 |

Row 20 repeats rows 8–17 immediately before issuance, under serialization with
registry publication and nonce reservation. If a repeated check fails, use that
row's original code, not `service_unavailable`. Signing errors use only the
latter. A clock-health failure is `clock_skew` even if the input timestamp is
otherwise plausible. `Retry-After` on 429 MUST be the smallest positive whole
seconds until both windows have room; 503 MAY include a bounded retry delay.

Audit failure is the sole terminal override: if recording a would-be refusal
fails, return `audit_unavailable` rather than its original code. Standard
precedence vectors assume healthy audit unless the vector expressly faults it.
After row 21 acknowledgement, the service MUST reacquire its admission
serialization and repeat rows 8–17 before releasing the signed JWT; registry
publication and signing-key cutover MUST share that serialization. A changed
verdict discards the JWT and records a refusal with that original code. The
service MUST also compare the signing-key generation captured at signing with
the active generation immediately before release. A paused signer or generation
mismatch cancels the pending issuance as `503 service_unavailable`; the signed
JWT MUST NOT be returned or re-signed implicitly. Keep its consumed nonce and
limiter debits, and append a refusal (an earlier committed issued audit line may
remain). Audit failure retains its terminal override. No service state lock is
held during off-host I/O. No failure releases a JWT.
All outcomes are audited as §9 permits.
Malformed HTTP framing is rejected by the HTTP server before this API; no
application verdict is promised for an uninterpretable HTTP request.

### 6.2 Added codes and loader diagnostics (normative)

All fifteen CIP registration codes are retained without renaming. Added API
codes cover contracts the CIP did not assign: `endpoint_not_found`,
`method_not_allowed` (routing); `request_too_large`, `unsupported_media_type`
(bounded transport); `registry_unavailable` (fail-closed registry);
`service_unavailable` (signer/runtime failure); `audit_unavailable` (issuance
without an audit is forbidden). These are not helper refusal codes.

Loader-only diagnostics are `enrollment_malformed`,
`enrollment_sigs_unsupported`, `enrollment_id_mismatch`,
`enrollment_signature_invalid`, `registry_conflict`, `registry_rollback`.
They distinguish schema, reserved future authority, id, publisher signature,
ambiguous authority and regression respectively. They are never HTTP successes;
loading any such candidate leaves admission unavailable as §4.4 requires.

## 7. Time, replay, concurrency and limits (normative)

The registrar MUST run as one replica. The old instance MUST stop admitting
before a replacement process is launched. Two concurrently admitting instances
are outside the restart-ordering premise; scaling requires a shared atomic
nonce store and a separately qualified design. Admission timestamps use integer
seconds: `now = floor(current UTC Unix time)` for one check pass. Clock evidence,
error bounds and monotonic holds MUST retain their required subsecond precision.

The only production clock evidence source MUST be the shared provider for the
**Platform time policy**, owned by the credential-broker project and intended
for `docs/time-policy.md` there (publication/link pending; Appendix C.4).
All three services use that provider through an evidence-source interface;
this specification does not define a second provider or a chrony parser.
Version 0 uses the policy's option A, requiring no root-granted per-source data.
A local healthy flag, wall timestamp or ordinary synchronization status alone
MUST NOT substitute for provider evidence. Test-injected health is not production
evidence. The policy requires:

- Every configured chrony source is marked `nts`; the selected tracking source
  matches an `nts` line by name or address. Otherwise evidence is unavailable.
- Tracking leap status is `Normal`, and the last synchronization is no older
  than 2048 seconds (equality permitted).
  A ceiling of twice the maximum poll interval of `2^10` seconds accommodates
  update jitter; age-related uncertainty is bounded separately through root
  distance in `delta_sample`.
- Offset magnitude is at most 0.5 seconds, and root distance is at most 1 second
  (both equalities permitted).
- Authority expires at sample time plus 5 minutes (300 seconds); at expiry it
  is no longer valid. Current health alone does not extend an expired sample.
- The provider reports healthy/unavailable and a nonnegative error bound
  `delta_sample = abs(offset) + root_distance`, without signed cancellation.
- A backward UTC step relative to monotonic within one boot exceeding 1 second
  raises the shared incident and hold. The registrar is stricter, as below.

The registrar MAY use stricter health thresholds. For version 0, the common
protected bound is `delta_cap = 0.5 + 1 = 1.5 seconds`. Configuration MUST NOT
raise it above the platform policy bound; such configuration MUST refuse startup.
Every admission, including the previous process's last admission, MUST require
current healthy, unexpired provider evidence with `0 <= delta_sample <= delta_cap`.
This common cap bounds both lifetimes; a new process's smaller sample does not
prove the previous process had that smaller error. The ordering proof below
assumes the provider's bound holds; the option-A evidence limitation remains.

Each process MUST pass its own startup provider check before starting a monotonic
hold of at least `H = 2 * delta_cap + 1 second = 4 seconds`. The one-second margin
is additional to the two clock-error bounds. A smaller `delta_sample` MUST NOT
shorten H. Wall-clock progress MUST NOT substitute for elapsed monotonic time.
No admission is allowed during the hold. After the hold, at the instant chosen
to fix process start, the startup check MUST pass again with healthy, unexpired
authority and `delta_sample <= delta_cap`. Otherwise the process stays fenced.
Only after that successful check is process start fixed. In every barrier rule,
**process start means this fixed UTC instant after the hold**, not launch time
or the first provider sample. Set
`start_barrier = floor(fixed process-start UTC time) + 31`: the 30-second maximum
accepted future skew plus one strict-boundary second. Requests with
`iat < start_barrier` MUST be refused as `clock_skew`, without skew allowance.
The barrier is immutable for that process; waiting MUST NOT lower or replace it.

To see the ordering premise, let a be the true time of the earlier last admission,
l the later process launch, and f its fixed instant. Single-instance exclusion
gives `a < l`, and the monotonic hold gives `f >= l + 2*delta_cap + 1`.
The earlier UTC reading is at most `a + delta_cap`; the fixed reading is at
least `f - delta_cap`. Thus the earlier reading is less than the fixed reading
minus one second. In particular, `old_now <= floor(fixed process-start UTC)`.
An earlier admissible proof had `iat <= old_now + 30`, hence
`iat < floor(fixed process-start UTC) + 31 = start_barrier`.
An empty nonce cache or later waiting cannot make that proof admissible again.
This depends on both lifetimes enforcing the common bound and on exclusive
serving; current health alone cannot establish a past unhealthy start.

Availability cost: after a successful initial check and an exactly 4-second
hold, with synchronized client/registrar clocks a fresh proof passes the barrier
only after more than 30 and at most 31 further seconds from the fixed instant:
`4 + (30, 31] = (34, 35] seconds`. A client clock 30 seconds behind can need
`4 + 31 + 30 = 65 seconds`; this replaces the former 61-second horizon.
A client 30 seconds ahead can first pass at the next whole registrar second
after the fixed instant, following the 4-second hold. No proof passes during
that instant's initial partial second: future skew still limits `iat <= now + 30`.
These are clock/barrier costs with the stated clock differences, prompt passing
checks and no extra scheduling delay, not a deadline guaranteeing readiness.
Evidence acquisition, excess hold/scheduling and transport latency add to them;
unavailable evidence can fence indefinitely.
Keymaker clients MUST replace the 61-second startup backoff horizon with
65 seconds plus their evidence/scheduling/transport margin, then obtain a fresh
proof and nonce. They MUST NOT replay an old proof indefinitely or bypass a
clock fence. Persistent refusal beyond that budget requires clock/readiness
diagnosis. A healthy provider does not clear a process-lifetime fence.

The admission skew bound remains 30 seconds. Future `iat = now + 30` is
accepted; `now + 31` is refused. `now = exp + 29` may pass; `now = exp + 30`
is expired. These are proof rules, not homeserver JWT leeway. Hosts, registrar
and homeserver MUST have monitored synchronization. The registrar MUST fence
admission (`clock_skew`) on any detected backward UTC step relative to monotonic,
including a step of at most 1 second that does not trigger the shared incident.
Step detection concerns a UTC discontinuity, not repeated integer-second
admission readings. False fences from smooth slew and measurement jitter concern
provider qualification and liveness, with no demonstrated safety gap; qualification
MUST include those controls. Loss of provider health, unavailable evidence, expired
authority or a reported error above delta_cap MUST also fence admission.
These are process-lifetime fences, including during startup. Restored health,
operator acknowledgement and waiting MUST NOT reopen that process or replace
its fixed barrier. Recovery requires verified provider health and a new process
that repeats both checks and the complete 4-second hold before fixing its own
start. No surviving evidence means no admission; an ordinary startup wait is
not a recovery timeout. Retained nonces MUST NOT be cleared to recover a clock.

On any process-lifetime clock fence, including during startup, the registrar
MUST stop admitting and follow the normal bounded shutdown drain: join pending
HTTP handlers and detached audit records, then close the sink only after both
joins succeed. After successful drain and sink closure it MUST exit with the
dedicated clock-fence code **75** and fixed diagnostic `registrar: clock fenced`,
without secrets or paths. Code 75 MUST be distinct from configuration, non-clock
startup and drain failure exits. A drain failure retains its existing non-zero
exit and diagnostic, MUST NOT report code 75, and MUST NOT close the sink under
pending work. The deployment supervisor MUST automatically restart on failure
only after the previous process has exited, preserving the single-replica premise
that old admission stops before new launch; a start rate limit MUST bound restart
loops, and a limit-stopped unit requires operator recovery. The replacement MUST
repeat both provider checks and the full hold as above. With prompt healthy
checks, the hold/check contribution is about 4 seconds plus provider sampling;
drain, supervisor backoff, scheduling and barrier waits add availability cost
without relaxing safety.

Option A establishes the selected source's NTS status from configuration,
not authenticated per-source NTS data. Misconfiguration or compromised source/
configuration evidence can invalidate the assumed UTC bound; this is a residual
risk, not proof of authenticated source operation. Option B requires separately
qualified root-granted per-source authentication data. Two concurrent instances
remain outside the proof even with healthy time evidence.
Monotonic clocks also measure limiter intervals and watchdogs. Version 0 uses
no durable replay cache or clock/admission-time high-water mark; the separate
durable registry high-water requirements in §4 remain unchanged.

Nonce identity is the canonical public-key string plus the 16 decoded nonce
bytes. Reserving that pair and testing absence MUST be atomic. An accepted
reservation is consumed even if signing, final revalidation, audit or delivery
subsequently fails. It MUST remain until `now >= request.exp + 30`; no prior
reclamation is allowed. While a pair is retained, a repeated nonce with another body/id is still replay.
Different keys may use the same random nonce. Request retries MUST obtain a
fresh proof and nonce; POST is not an idempotent JWT-retrieval API. After a
restart the empty nonce cache is safe only with the start-barrier rule and a
healthy nonregressing clock. Concurrent duplicates can produce at most one JWT.
The homeserver does not enforce single-use `jti`; JWT replay remains a residual.

Defaults are sliding monotonic windows of 60 seconds: **10 attempts per key,
3 per exact name**. An event exactly 60 seconds old is removed before counting.
Both budgets start empty. Row 18 tests both, and atomically debits both only if
both have capacity. Every attempt reaching row 18 that passes its budget check
counts, including later replay/signing/audit failures. Earlier refusals do not
count toward these authenticated budgets; a rate-limited refusal debits neither
and does not extend the window. Ingress connection/byte limits MUST separately
bound unauthenticated traffic and audit growth without trusting supplied names.
Operators MAY lower these two defaults only to whole-number capacities in
`1..10` per key and `1..3` per name. Zero, negative, fractional or out-of-range
capacities MUST be rejected as configuration errors before serving admission;
they MUST NOT produce an infinite or undefined `Retry-After`. Changes MUST be
explicit configuration and recorded in deployment/test evidence. Vector defaults
are the values above unless a row explicitly configures lower capacities.

## 8. Login JWT and signing-key lifecycle (normative)

A JWT MUST be compact JWS with three canonical unpadded base64url segments.
The protected header is exactly `{"alg":"EdDSA","typ":"JWT"}`. There is no
`kid`, `jku`, `jwk`, `x5u` or unprotected header. The payload has exactly:

| Claim | Value |
| --- | --- |
| `iss` | String `swarma-registrar`. |
| `aud` | Array containing exactly the configured server-name string. |
| `sub` | The accepted lowercase localpart, never a full mxid. |
| `iat` | JSON integer Unix second at JWT issuance (not the proof's timestamp). |
| `nbf` | Exactly the JWT `iat`. |
| `exp` | Exactly the JWT `iat + 120`. |
| `jti` | The registration envelope id, including `sha256:`. |

Header and payload MUST use CCJ-1 bytes before JWS encoding. Ed25519 signs
ASCII `base64url(header) + "." + base64url(payload)`, as ordinary JWS, not the
registration preimage. No request field can choose an issuer, algorithm,
signing key, arbitrary subject or a different token lifetime. The proof lifetime
and JWT lifetime are separate: the JWT always lasts 120 nominal seconds.

The registrar's protected signing file MUST hold a PKCS#8 PEM Ed25519 private
key, mode 0600 under its non-agent service account, in a 0700 directory. The
homeserver receives only the corresponding SubjectPublicKeyInfo PEM public key.
No host, station or enrollment-publisher secret is held by the registrar.
Signer and homeserver verification key MUST switch together without overlapping
verification keys; §10 explains the one-key implementation. On unknown/missing
key material issuance fails closed. A rotation runbook MUST preserve audit and
nonce state and MUST NOT change the registry rollback high-water.

## 9. Audit and failure ordering (normative)

Every received admission request and routing refusal MUST have a bounded,
append-only audit entry. Use one CCJ-1 object followed by LF per line. Fields
are exactly `v` (integer 1), `seq` (positive increasing integer), `at` (§3 time),
`instance` (random 16-byte base64url process identifier), `jti` (validated
recomputed id or null), `key_id` (`sha256:` plus lowercase SHA-256 of the
canonical public-key string, or null), `host` (authenticated host or null),
`name` (validated localpart or null), `outcome` (`issued` or `refused`),
`code` (`issued` or refusal code), `http_status` (integer), `registry_revision`
(loaded commit id or null), `jwt_iat`, `jwt_exp` (integer seconds on issuance,
null otherwise), `request_bytes` (observed byte count, capped at 65,537), and
`prev_hash` (lowercase SHA-256 hex of the previous complete line, or 64 zeroes
at the first entry). Unknown/unverified identity MUST remain null; raw malformed
input MUST NOT be copied into logs. Restrict audit reader access.

Audit MUST NOT contain JWTs, access/refresh tokens, passwords, signatures,
private keys, raw nonces, request bodies or arbitrary exception messages.
A `jti` is a public request id, not a token. A sink MUST validate monotonic seq
and hash-chain continuity; line hashing includes the terminating LF.

Before returning a JWT, the service MUST durably append the issued entry locally
and obtain durable acknowledgement of that exact line from an authenticated
off-host append-only sink. Failure means no JWT leaves the service and the
nonce stays consumed. A locally recorded `issued` line means an issuance was
committed, not that a client received the credential. Network loss may make
receipt unknowable; it MUST NOT trigger replay of a JWT response.

When the off-host sink is unavailable, refusals MAY be durably spooled locally
for later shipping; issuance MUST fail closed as `audit_unavailable`. A failed
issuance attempt MUST also append a refused event when local storage works;
this may follow a committed issued entry if its off-host acknowledgement was
lost. If a would-be refusal cannot be appended durably, replace its HTTP code
with `503 audit_unavailable` and stop accepting new requests until local
recording recovers. Storage failure can prevent the attempted failure record
itself: operators MUST see a readiness failure, never a false claim that an
unwritten event was audited. Spool replay MUST preserve sequence and bytes.
Admission and sink operations MUST have finite deadlines (default 5 seconds
total per request); timeout obeys the same no-release rule.

## 10. Homeserver operator contract (normative; source findings informative)

### 10.1 Configuration request (normative target)

The operator MUST request this configuration with the real server name and
registrar **public** PEM substituted. This is a configuration target, not a
claim that stock v1.9.3 meets all requirements in §10.3.

```toml
[global]
server_name = "example.org"
allow_registration = false
allow_guest_registration = false
access_token_ttl = 86400
# Leave registration_token, registration_token_file,
# registration_shared_secret and registration_shared_secret_file unset.

[global.jwt]
enable = true
format = "EDDSA"
algorithm = "EdDSA"
key = """-----BEGIN PUBLIC KEY-----
<registrar Ed25519 SubjectPublicKeyInfo PEM base64>
-----END PUBLIC KEY-----"""
register_user = true
issuer = ["swarma-registrar"]
audience = ["example.org"]
require_exp = true
require_nbf = true
validate_exp = true
validate_nbf = true
validate_signature = true
```

The operated homeserver MUST provide access-token expiry after 86,400 seconds
without refresh-token issuance and MUST refuse JWT login for deactivated
accounts. A reviewed homeserver change MUST provide both requirements and be
qualified before deployment (§10.3); no configuration keys for that change are
specified here. Specification, vectors and service implementation may continue
while deployment is blocked.

Agent login requests MUST NOT request refresh tokens; credentials MUST NOT
persist one. The accepted access-token lifetime is 86,400 seconds, with no
agent refresh-token issuance. Setting `refresh_token_ttl = 0` MUST NOT be used
as a supposed refresh-token disable switch: in this version it means no expiry
of a refresh token. Human SSO provisioning is separately operator-controlled;
it MUST NOT open agent self-registration. A future bridge's appservice
namespace MUST be reconciled explicitly with this transitional namespace.

### 10.2 Verified upstream behavior (informative)

Source inspection used tuwunel **v1.9.3**, commit
[`7801b8ec6f7773d90b1bbfeeb352012d6e004e96`](https://github.com/matrix-construct/tuwunel/tree/7801b8ec6f7773d90b1bbfeeb352012d6e004e96).
These findings are static inspection, not live-server or interoperability tests.

| Source at that commit | Observed behavior |
| --- | --- |
| [`src/api/client/session/jwt.rs`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/src/api/client/session/jwt.rs), `init_verifier`, `init_validator` | `EDDSA` selects Ed25519 PEM decoding. Allowed header `alg` comes independently from `config.algorithm`; it MUST be set to `EdDSA` (default is HS256). `Validation::new` allows that single algorithm. |
| Same file, `Claim`, `validate_user`, `handle_login` | Reads `sub` as a string, lowercases it, parses with the configured server name. The documented subject is a localpart; this draft emits only that form. If absent locally, `register_user=true` creates an account with password marker `*` and origin `jwt`; false refuses unknown users. It does not re-register an existing account. |
| Same file, `init_validator` | Nonempty issuer/audience lists make `iss`/`aud` required and checked. `require_exp`/`require_nbf` make claims required; `validate_exp`/`validate_nbf` separately enable their checks. It does not check `iat` or consume `jti`. |
| [`src/core/config/mod.rs`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/src/core/config/mod.rs), `JwtConfig` | One configured verification key; JWT settings are declared reloadable. `validate_signature=false` bypasses verification in debug builds; this draft requires true. No leeway configuration field exists. |
| [`Cargo.lock`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/Cargo.lock), jsonwebtoken 11.0.0 | Locks the validator dependency used below. |
| [`src/api/client/session/mod.rs`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/src/api/client/session/mod.rs), `login_route`; [`src/service/users/device.rs`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/src/service/users/device.rs), `generate_access_token` | Passes the client's `refresh_token` boolean as the `expires` argument. Only true assigns `access_token_ttl`; any assigned expiry also generates a refresh token. False yields no expiry. |
| [`src/api/client/session/password.rs`](https://github.com/matrix-construct/tuwunel/blob/7801b8ec6f7773d90b1bbfeeb352012d6e004e96/src/api/client/session/password.rs), `password_login` | Existing `jwt`-origin accounts do not permit password login. Existing password-origin accounts do not automatically lose their password on JWT login. |
| `jwt.rs`, `handle_login`; `session/mod.rs`, `login_route` | JWT login has no deactivation check in this version; the common path checks account locks. Deactivation alone cannot be asserted to block a still-valid JWT. |

The dependency [jsonwebtoken v11.0.0, commit
`900010fb1be550ec2cfa8c32038eb154f9ef56d7`, `src/validation.rs`](https://github.com/Keats/jsonwebtoken/blob/900010fb1be550ec2cfa8c32038eb154f9ef56d7/src/validation.rs)
sets **60 seconds leeway** by default. tuwunel does not override it. Expiry
rejects when `exp < now - 60`; not-before rejects when `nbf > now + 60`.
Equality passes both checks. Thus a nominal 120-second JWT can be accepted
through `exp + 60` inclusive. `iss` and `aud` are exact membership checks;
array audience succeeds when at least one member matches. This profile emits
one audience only. The dependency's [`src/decoding.rs`](https://github.com/Keats/jsonwebtoken/blob/900010fb1be550ec2cfa8c32038eb154f9ef56d7/src/decoding.rs)
checks header `alg` against the allowed list; it does not use `kid` to obtain a
key or enforce `typ=JWT`. Registrar emission rules remain stricter than those
acceptance checks.

### 10.3 Activation gates and divergences (normative)

**Access-token expiry without refresh tokens is not supported by stock
v1.9.3's inspected login path.** The `access_token_ttl` setting alone cannot
meet §10.1. The chosen path is a reviewed change to the operated homeserver
providing both access-token expiry without refresh-token issuance and refusal
of JWT login for deactivated accounts. Deployment MUST remain blocked until
that change is qualified. Specification, vectors and service code continue
meanwhile. Discarding a refresh token client-side, requesting one secretly, or
asserting a CLI timeout is server-side expiry MUST NOT be used as a substitute.

The stock 60-second JWT leeway is accepted (decision HS3). It extends nominal
bearer validity and is separate from the registrar's 30-second proof skew.
Revocation MUST account for a pending JWT being usable through `exp + 60`.
The pinned stock version does not reject JWT login for deactivated accounts;
that refusal is a requirement of the chosen homeserver change, not a claim
about stock behavior. These are source-confirmed divergences from a naive
reading of the CIP, not unverified claims. No live compatibility claim is
made. Reload atomicity, revocation ordering and end-to-end account behavior
still require isolated qualification; never test against a production server.

## 11. Revocation, rotation and threats (normative)

### 11.1 Procedures (normative)

For host revocation the operator MUST publish a signed `seq + 1` record with
`state=revoked`, advance the reviewed registry pin at registrar and Keymaker,
and confirm both have fenced that host before declaring new proof issuance
stopped. A missing acknowledgement is unresolved revocation. All devices of
that host's accounts, including explicit legacy names, MUST be logged out;
deactivate or lock accounts as required by the qualified homeserver path.
Review audit since the last known-good time. A registrar tombstone stops new
JWTs but does not cancel outstanding JWTs or existing access tokens. On stock
v1.9.3, lock/contain the affected accounts while outstanding JWTs can still log
in, then repeat device logout after the latest issued `exp + 60` has passed.
Do not rely on deactivation alone. Unlocking/rehabilitating a revoked host label
is outside this version. Loss of complete issue history requires conservative
containment rather than guessing the last outstanding expiry.

For host-key rotation, publish a higher-sequence active enrollment containing
old and new keys with overlapping half-open windows; install the pin at both
consumers, switch Keymaker to the new key, then publish another higher-sequence
record dropping the old key after the overlap. Old requests then yield
`key_not_enrolled`; retain old records for audit and non-reassignment. Emergency
compromise MAY remove the old key immediately. No private key is transported to
the registrar, and no host tombstone is needed for normal rotation.

For registrar-key rotation, pause issuance, replace the homeserver public key
and registrar private key as one coordinated operation, verify the installed
pair, then resume. Cutover MUST advance the active signing-key generation under
the release serialization in §6.1, even when restoring earlier key bytes. This
generation is internal state, not a JWT `kid`. Pending issuance signed by an earlier
generation is cancelled, not drained or returned as an outstanding token; its
client receives `service_unavailable` (subject to the audit override) and obtains
a fresh proof after recovery. Previously released JWTs remain outstanding old
JWTs. During mismatch, login MUST fail closed. Already issued old
JWTs cease to verify once the public key changes; new JWTs require the new key.
Do not promise an automatic outage bound: coordinated healthy rollout aims for
120 seconds, but operator/reload failure can extend it. Existing Matrix access
tokens survive signing-key rotation; compromise recovery MUST separately log
out affected devices, inspect audit and secure the signer before resuming.

### 11.2 Threat mapping (normative)

| Threat | Required boundary and residual |
| --- | --- |
| Compromised host/helper | Exact key-to-host enrollment and names prevent other-host namespace admission. Revoke the host/key and terminate carrier sessions. Authorized names on that host remain exposed until containment. |
| Compromised registrar | Its signing key can impersonate arbitrary users. Minimize service surface, isolate the key, ship audit off-host, rotate and terminate affected sessions. The homeserver cannot reconstruct enrollment checks from a JWT. |
| Prompt injection asks for its permitted name | UID-scoped Keymaker prevents crossing station UIDs; grants and carrier room policy control actions. Possession proof does not detect malicious requests within permitted authority. |
| Proof replay/concurrent retries/restart | Atomic consumed nonces, expiry/skew bounds, start barrier and single replica. A captured JWT remains replayable within homeserver validity; `jti` is audit correlation only. |
| Registry tampering/rollback | Reviewed signed pin, separate publisher pin, whole-snapshot validation, durable history/tombstones and restore fence. A compromised authorized publisher/maintainer or operator is outside this trust claim. |
| Clock manipulation | Platform provider evidence, common 1.5-second error cap, 4-second monotonic pre-start hold, fixed barrier and permanent fence on any detected backward step or invalid/expired authority. Option A infers NTS from configuration, not authenticated per-source data; a compromised source can invalidate the error-bound premise. Concurrent instances are outside the proof (§7). |
| DoS / audit exhaustion | Bounded request/registry/depth, authenticated sliding limits, independent ingress limits and finite audit deadlines. Audit unavailability deliberately denies issuance. |
| Bearer interception / retained sessions | TLS, no token logging, bounded JWT validity and explicit logout. Access-token expiry is an activation blocker on the pinned source; do not claim a bound before qualification. |

### 11.3 CLI and cutover guidance (informative)

`identity ensure` and re-login on `M_UNKNOWN_TOKEN` obtain a fresh proof from
Keymaker, POST it, then submit `{"type":"org.matrix.login.jwt","token":"<jwt>",
"refresh_token":false}` to the Matrix login endpoint. A JWT is kept only in
memory and never printed, traced or placed in a command-line argument. The
credential file holds only `user_id`, `access_token`, `device_id`; it is written
atomically with mode 0600 in a private directory. It contains no password,
refresh token, host key or JWT. A successful second login must reach the same
mxid. The desired expiring-session path remains gated by §10.3.

Cutover closes token registration, disables/resets passwords and logs out all
devices for accounts created through the previous path. Existing password-origin
accounts need explicit operator remediation; JWT login alone does not do it.
Legacy explicit names remain exact exceptions until renamed and removed in a
higher-sequence enrollment. Removing enrollment does not itself remove an
existing carrier session or account.

## Appendix A. Vector fixture contract (normative plan)

This task plans vectors; it creates no vector files or cryptographic outputs.
The next task MUST record canonical bytes, id, signature and expected verdict
for every row in Appendix B. Test keys MUST derive only from fixed published
seeds (Ed25519: RFC 8032 test material; P-256: a documented public test scalar,
never a generated operational key). Controls are definitions of future vectors.

Unless a row says otherwise, use audience `example.org`, host `host-a`, name
`host-a_project_dev`, `iat=2030-01-01T00:01:00Z`,
`exp=2030-01-01T00:03:00Z`, registrar
`now=2030-01-01T00:01:00Z`, and
`start_barrier=2030-01-01T00:00:00Z`. The key window is
`[2030-01-01T00:00:00Z,2031-01-01T00:00:00Z)`.
An active host's sequence is 1, its prefix is `host-a_`, its explicit list
contains `legacy.dev`, and its UID map is `[{"uid":1001,"names":["host-a_project_dev"]}]`.
It is a configured station host. Registry/publisher pins and audit are healthy;
rate windows and nonce cache start empty. A revoked control retains this valid
key window. All dependent ids/signatures MUST be rebuilt after a deliberate
body edit unless id/signature invalidity is the defect. A positive enrollment
control includes a valid offline publisher signature and verified commit pin.

Bare numeric timestamps in restart rows are integer seconds after
`2030-01-01T00:00:00Z`; fractional start values are not wire timestamps.
The legacy fixture start, barrier and clock-health fields are abstract post-hold
admission inputs: process start denotes the fixed instant defined in §7.
These fixtures test barrier, skew and fence rules; they do not execute or qualify
the provider checks/monotonic hold and are not production startup traces.
R125 is the explicit example: its restart 0.2 seconds after the last old
admission is not realizable under the 4-second hold with the common bound;
it remains a correct isolated test of `iat = barrier - 1` refusal. All 310
existing rows and their vector bytes remain unchanged. The real startup
protocol is planned separately in B.3.
The machine-readable declaration below enumerates every legacy row carrying
these inputs, including enrollment and codec rows with shared fixture defaults.

<!-- abstract-post-hold-rows-v1: ["E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08", "E09", "E10", "E100", "E101", "E102", "E103", "E104", "E105", "E106", "E107", "E108", "E109", "E11", "E110", "E111", "E112", "E113", "E114", "E12", "E13", "E14", "E15", "E16", "E17", "E18", "E19", "E20", "E21", "E22", "E23", "E24", "E25", "E26", "E27", "E28", "E29", "E30", "E31", "E32", "E33", "E34", "E35", "E36", "E37", "E38", "E39", "E40", "E41", "E42", "E43", "E44", "E45", "E46", "E47", "E48", "E49", "E50", "E51", "E52", "E53", "E54", "E55", "E56", "E57", "E58", "E59", "E60", "E61", "E62", "E63", "E64", "E65", "E66", "E67", "E68", "E69", "E70", "E71", "E72", "E73", "E74", "E75", "E76", "E77", "E78", "E79", "E80", "E81", "E82", "E83", "E84", "E85", "E86", "E87", "E88", "E89", "E90", "E91", "E92", "E93", "E94", "E95", "E96", "E97", "E98", "E99", "PC1", "PC10", "PC2", "PC3", "PC4", "PC5", "PC6", "PC7", "PC8", "PC9", "PE1", "PE10", "PE11", "PE12", "PE13", "PE14", "PE15", "PE2", "PE3", "PE4", "PE5", "PE6", "PE7", "PE8", "PE9", "PR1", "PR10", "PR11", "PR12", "PR13", "PR14", "PR15", "PR16", "PR17", "PR18", "PR19", "PR2", "PR20", "PR21", "PR22", "PR23", "PR24", "PR25", "PR26", "PR27", "PR28", "PR29", "PR3", "PR30", "PR31", "PR32", "PR33", "PR4", "PR5", "PR6", "PR7", "PR8", "PR9", "R01", "R02", "R03", "R04", "R05", "R06", "R07", "R08", "R09", "R10", "R100", "R101", "R102", "R103", "R104", "R105", "R106", "R107", "R108", "R109", "R11", "R110", "R111", "R112", "R114", "R115", "R116", "R117", "R118", "R119", "R12", "R120", "R121", "R122", "R123", "R124", "R125", "R126", "R127", "R128", "R129", "R13", "R130", "R131", "R132", "R133", "R134", "R135", "R136", "R137", "R138", "R139", "R14", "R15", "R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27", "R28", "R29", "R30", "R31", "R32", "R33", "R34", "R35", "R36", "R37", "R38", "R39", "R40", "R41", "R42", "R43", "R44", "R45", "R46", "R47", "R48", "R49", "R50", "R51", "R52", "R53", "R54", "R55", "R56", "R57", "R58", "R59", "R60", "R61", "R62", "R63", "R64", "R65", "R66", "R67", "R68", "R69", "R70", "R71", "R72", "R73", "R74", "R75", "R76", "R77", "R78", "R79", "R80", "R81", "R82", "R83", "R84", "R85", "R86", "R87", "R88", "R89", "R90", "R91", "R92", "R93", "R94", "R95", "R96", "R97", "R98", "R99"] -->

For the legacy restart traces the prior process has injected start offset 0
(old barrier 31), before the stated first proof. Unless a row explicitly injects
clock failure, its admission clock-health inputs are healthy and all other
proof/enrollment/audit inputs valid. Only the stated restart clears nonce and
limiter memory. Later replay MUST NOT alter proof bytes, id, signature or nonce.

A row with a temporal defect MUST keep both `iat` and current time inside the
key window unless the window itself is under test. Future/expiry controls MUST
adjust `start_barrier` so the restart check does not mask the intended result.
A name-length control MAY use a longer configured audience and an explicit
legacy name to reach precisely the mxid byte boundary. Body input order and
wire escaping can vary without changing signed canonical bytes.

Each stateful fixture MUST declare initial state, scheduled external/operator
changes, and exact expected final state in these separate categories:

- **Authority:** enrollment snapshot, pins, high-water/tombstones, signing-key
  generation and clock policy. A refused request MUST NOT mutate authority.
  Scheduled operator changes (for example revocation or key cutover) are explicit
  fixture inputs, not prohibited request effects. A rejected registry candidate
  MUST leave the last accepted authority/high-water unchanged; readiness may be
  fenced, but stale authority MUST NOT be used.
- **Admission accounting:** consumed nonce pairs and limiter events. Failure
  before row 18 changes neither. Passing row 18 debits both budgets; a refusal
  there debits neither. Row 19 inserts only an absent nonce, keeps an existing
  pair on replay, and never removes a reserved pair after later failure. A
  fixture MUST explicitly state any time-driven expiry/pruning.
- **Audit:** expected appended lines and acknowledgements, including permitted
  issued-then-refused pairs and the possibility of no append on local failure.
  A refusal is not an assertion that audit bytes remain unchanged.
- **Readiness:** a fixture MUST state any required clock, signer, loader or
  audit fence independently of authority and accounting.

Refusals MUST return no JWT. All stateful rows MUST instantiate this oracle,
including their paired positive controls; they MUST NOT merely assert that
all state stayed unchanged. The following traces pin the subtle cases:

| Row | Immutable authority / scheduled inputs | Nonce and limiter oracle | Audit and readiness oracle |
| --- | --- | --- | --- |
| R88 | No operator change; authority unchanged. Seed two accepted attempts for the same name, using distinct nonces; the first nonce is retained. | Replay the first proof: both budgets debit their third event, nonce set stays at two. A following fresh proof is rate-limited: no fourth debit and no new nonce. Key capacity remains 10. | After the two seed issued lines, append one nonce_replayed and one rate_limited refusal; readiness stays healthy. |
| R99 | No operator change; authority unchanged. Start with empty budgets/cache; signer fails after nonce reservation, then recovers for the retry. | First attempt consumes one nonce and one event per budget. Identical retry debits a second event per budget and refuses replay; the nonce set still has exactly one pair. | Append service_unavailable then nonce_replayed refusals; healthy audit, recovered signer. |
| R106 | No operator change; authority unchanged. Id mismatch fails before row 18. | No nonce reservation or budget debit. | Inject local refusal-append failure: no new local/off-host line; return audit_unavailable and fence readiness. Existing audit bytes remain unchanged. |

The remaining stateful rows use these explicit oracle profiles; no profile
permits request-driven authority mutation or a JWT on refusal. A named row
profile refines the general stage profile; unmentioned state stays unchanged:

| Rows / reached stage | Authority | Nonce / limiter changes | Audit / readiness |
| --- | --- | --- | --- |
| All enrollment rejection rows | Accepted snapshot, pins and high-water stay unchanged. | Neither admission cache nor budgets change. | No admission-audit event; restricted loader diagnostic is permitted; admission fenced. |
| All enrollment positive controls PE1–PE15 | Install only the exact validated candidate and its durable high-water. | Admission accounting unchanged. | No admission-audit event; readiness healthy. |
| Registration refusal before row 18, excluding R106 | Unchanged except explicit scheduled operator inputs. | No reservation or debit. | One refusal append/ack with healthy audit; R79/R80 require clock fencing, R94 requires registry fencing. |
| R86/R87/R105/R111/R129, plus the final attempt in R88 | Unchanged. | Budget-full refusal debits neither and inserts no nonce; R111 checks release time is not extended. | One rate_limited refusal, healthy readiness. |
| R83/R84, plus R99 retry | Unchanged. | One debit per budget; retained nonce unchanged. | One nonce_replayed refusal; no issued line for this attempt. |
| R85/PR12 concurrent pair | Unchanged. | Two debits per budget in total; exactly one nonce insertion. | One issued and one nonce_replayed line; exactly one response contains a JWT. |
| R95/R96/R97/R98/R123/R128 after reservation | No request-driven change; revocation/cutover inputs remain effective. | One debit per budget and one retained nonce despite failure. | R95 signer refusal, R96 unacknowledged issued line plus locally spooled audit refusal, R97 no new line on local failure and audit fence; R98 revokes before row 20 and appends only host_revoked; R123/R128 acknowledge an issued line then append their final refusal. No JWT release. |
| All otherwise unspecified registration positive controls | Unchanged. | One debit per budget and one inserted nonce for the successful attempt. | One issued line acknowledged off-host; healthy readiness. |
| PR13 | Unchanged. | At now=60 prune the oldest of ten seeded key events (one at 0, nine at 1), then debit one new event. Use a new permitted name with empty name budget; retained nonce pairs are not pruned. | One issued line for the new request; healthy readiness. |
| PR14 | Unchanged. | Two seeded same-name events/nonces become three after the fresh successful proof. | One additional issued line; healthy readiness. |
| PR18 | Unchanged. | Existing pair for key A stays; same nonce inserts a distinct pair for key B, debits B and the shared-name budget once (both below cap). | One additional issued line; healthy readiness. |
| R124–R127 / PR22–PR24 restart traces | Authority unchanged; explicit process restart is an input. | Restart clears cache/budgets. Rejected replay/future proof debits and reserves nothing; fresh successful control inserts/debits once. | Persistent old audit lines remain; append the stated refusal or fresh issuance. Healthy clocks/readiness. |
| R130–R133 / PR27 clock-recovery traces | Authority unchanged. Explicit clock failure/recovery and process restarts are fixture inputs; the unhealthy-start or tripped-fence process never reopens. | Each restart clears cache/budgets. Clock refusals reserve/debit nothing; PR27 inserts/debits once for its fresh proof. | Keep prior audit lines; append/ack one refusal per rejected attempt or one issued line for PR27. The old process stays fenced even after synchronized UTC returns; only the new verified-start process becomes ready. |

Loader failures MUST not install partial authority. The positive control column
names an actual planned row, not agreement with a second implementation. Every planned vector is a separate
row; transport/state rows use the affected signing domain even when their
fixture is not itself a signed object.

## Appendix B. Negative-first vector plan (normative plan)

Canonicalization-only rows test the CCJ-1 codec independently of the body
schema; their success is `accept (codec)`. All other accepts mean admission,
registry installation or the specified emission assertion, not just parsing.

The two-domain byte-vector plan contains **310 rows**: registration/1 has 138 negative and 33 positive
rows; enrollment/1 has 114 negative and 25 positive rows, including the ten
codec controls. These are planned rows, not a count of implemented fixtures.
Section B.2 adds separate witness-lifecycle plans, not byte-vector files.

For the leading-hyphen rows below, enroll the station host `-node` with prefix
`-node_`, an active valid key, and explicit list `["legacy.dev"]`; rebuild the
signed request and publisher-signed enrollment after every body change as in
Appendix A. Registration rows keep the enrollment UID map at
`[{"uid":1001,"names":["legacy.dev"]}]` so a request-name defect cannot invalidate
the registry first. Enrollment rows instead put the stated structured candidate
in that UID map, except where the explicit-list defect is stated.

For PR29, PE15, R134 and E112, configure the audience as four DNS labels:
63 `a` characters, 63 `b` characters, 63 `c` characters, and 43 `d` characters,
joined by three dots (235 ASCII bytes); request `aud` matches it exactly.
`-node_project_role` is 18 bytes, giving a 255-byte mxid; appending `x` gives
256 bytes. The legacy explicit/UID-map control `legacy.dev` still fits that
audience. All other prerequisites and healthy audit use Appendix A defaults.

| Id | Domain | Rule | Defect / boundary | Expected result | Positive control |
| --- | --- | --- | --- | --- | --- |
| R01 | registration/1 | CCJ duplicate keys | Duplicate body member | registration_malformed | PR1 |
| R02 | registration/1 | CCJ escaped duplicate | Two spellings decode to the same member name | registration_malformed | PR1 |
| R03 | registration/1 | CCJ UTF-8 | Invalid UTF-8 byte sequence | registration_malformed | PR1 |
| R04 | registration/1 | CCJ Unicode | Lone surrogate escape | registration_malformed | PR1 |
| R05 | registration/1 | CCJ number token | Fractional number token in an otherwise integer position | registration_malformed | PR1 |
| R06 | registration/1 | CCJ number token | Integral-valued decimal token 1.0 | registration_malformed | PR1 |
| R07 | registration/1 | CCJ number token | Exponent token 1e0 | registration_malformed | PR1 |
| R08 | registration/1 | CCJ negative zero | Numeric token -0 | registration_malformed | PR1 |
| R09 | registration/1 | CCJ safe integer upper bound | Integer 9007199254740992 | registration_malformed | PR1 |
| R10 | registration/1 | CCJ safe integer lower bound | Integer -9007199254740992 | registration_malformed | PR1 |
| R11 | registration/1 | Unknown envelope member | Extra top-level member | registration_malformed | PR1 |
| R12 | registration/1 | Unknown body member | Extra body member | registration_malformed | PR1 |
| R13 | registration/1 | Required envelope members | Missing sig | registration_malformed | PR1 |
| R14 | registration/1 | Required body members | Missing type | registration_malformed | PR1 |
| R15 | registration/1 | JSON type | Body is an array | registration_malformed | PR1 |
| R16 | registration/1 | JSON type | Required string is null | registration_malformed | PR1 |
| R17 | registration/1 | Input BOM | UTF-8 BOM before object | registration_malformed | PR1 |
| R18 | registration/1 | Depth cap | Input reaches nesting depth 17 | registration_malformed | PR1 |
| R19 | registration/1 | Base64url alphabet | Signature uses + instead of URL alphabet | registration_malformed | PR1 |
| R20 | registration/1 | Base64url padding | Signature ends in = | registration_malformed | PR1 |
| R21 | registration/1 | Base64url trailing bits | Signature decodes to right bytes but has nonzero unused bits | registration_malformed | PR1 |
| R22 | registration/1 | Signature size | Signature decodes to 63 bytes | registration_malformed | PR1 |
| R23 | registration/1 | Id syntax | Id uses uppercase hex | registration_malformed | PR1 |
| R24 | registration/1 | Id syntax | Id hash is 63 hexadecimal digits | registration_malformed | PR1 |
| R25 | registration/1 | Type discriminator | Wrong body type | registration_malformed | PR1 |
| R26 | registration/1 | Timestamp fraction | Required timestamp has fractional seconds | registration_malformed | PR1 |
| R27 | registration/1 | Timestamp zone | Required timestamp uses +00:00 | registration_malformed | PR1 |
| R28 | registration/1 | Timestamp grammar | Required timestamp uses lowercase z | registration_malformed | PR1 |
| R29 | registration/1 | Timestamp calendar | Required timestamp has February 30 | registration_malformed | PR1 |
| R30 | registration/1 | Timestamp range | Required timestamp has second 60 | registration_malformed | PR1 |
| R31 | registration/1 | Timestamp year | Required timestamp uses year 1969 | registration_malformed | PR1 |
| E01 | enrollment/1 | CCJ duplicate keys | Duplicate body member | enrollment_malformed | PE1 |
| E02 | enrollment/1 | CCJ escaped duplicate | Two spellings decode to the same member name | enrollment_malformed | PE1 |
| E03 | enrollment/1 | CCJ UTF-8 | Invalid UTF-8 byte sequence | enrollment_malformed | PE1 |
| E04 | enrollment/1 | CCJ Unicode | Lone surrogate escape | enrollment_malformed | PE1 |
| E05 | enrollment/1 | CCJ number token | Fractional number token in an otherwise integer position | enrollment_malformed | PE1 |
| E06 | enrollment/1 | CCJ number token | Integral-valued decimal token 1.0 | enrollment_malformed | PE1 |
| E07 | enrollment/1 | CCJ number token | Exponent token 1e0 | enrollment_malformed | PE1 |
| E08 | enrollment/1 | CCJ negative zero | Numeric token -0 | enrollment_malformed | PE1 |
| E09 | enrollment/1 | CCJ safe integer upper bound | Integer 9007199254740992 | enrollment_malformed | PE1 |
| E10 | enrollment/1 | CCJ safe integer lower bound | Integer -9007199254740992 | enrollment_malformed | PE1 |
| E11 | enrollment/1 | Unknown envelope member | Extra top-level member | enrollment_malformed | PE1 |
| E12 | enrollment/1 | Unknown body member | Extra body member | enrollment_malformed | PE1 |
| E13 | enrollment/1 | Required envelope members | Missing sig | enrollment_malformed | PE1 |
| E14 | enrollment/1 | Required body members | Missing type | enrollment_malformed | PE1 |
| E15 | enrollment/1 | JSON type | Body is an array | enrollment_malformed | PE1 |
| E16 | enrollment/1 | JSON type | Required string is null | enrollment_malformed | PE1 |
| E17 | enrollment/1 | Input BOM | UTF-8 BOM before object | enrollment_malformed | PE1 |
| E18 | enrollment/1 | Depth cap | Input reaches nesting depth 17 | enrollment_malformed | PE1 |
| E19 | enrollment/1 | Base64url alphabet | Signature uses + instead of URL alphabet | enrollment_malformed | PE1 |
| E20 | enrollment/1 | Base64url padding | Signature ends in = | enrollment_malformed | PE1 |
| E21 | enrollment/1 | Base64url trailing bits | Signature decodes to right bytes but has nonzero unused bits | enrollment_malformed | PE1 |
| E22 | enrollment/1 | Signature size | Signature decodes to 63 bytes | enrollment_malformed | PE1 |
| E23 | enrollment/1 | Id syntax | Id uses uppercase hex | enrollment_malformed | PE1 |
| E24 | enrollment/1 | Id syntax | Id hash is 63 hexadecimal digits | enrollment_malformed | PE1 |
| E25 | enrollment/1 | Type discriminator | Wrong body type | enrollment_malformed | PE1 |
| E26 | enrollment/1 | Timestamp fraction | Required timestamp has fractional seconds | enrollment_malformed | PE1 |
| E27 | enrollment/1 | Timestamp zone | Required timestamp uses +00:00 | enrollment_malformed | PE1 |
| E28 | enrollment/1 | Timestamp grammar | Required timestamp uses lowercase z | enrollment_malformed | PE1 |
| E29 | enrollment/1 | Timestamp calendar | Required timestamp has February 30 | enrollment_malformed | PE1 |
| E30 | enrollment/1 | Timestamp range | Required timestamp has second 60 | enrollment_malformed | PE1 |
| E31 | enrollment/1 | Timestamp year | Required timestamp uses year 1969 | enrollment_malformed | PE1 |
| R32 | registration/1 | Id derivation | One valid hex digit of id changed | registration_id_mismatch | PR1 |
| R33 | registration/1 | Domain separation | Sign enrollment domain; recompute registration id correctly | registration_signature_invalid | PR1 |
| R34 | registration/1 | Body extraction | Sign full envelope instead of domain + LF + body | registration_signature_invalid | PR1 |
| R35 | registration/1 | Preimage termination | Sign preimage with an extra terminal LF | registration_signature_invalid | PR1 |
| R36 | registration/1 | Key algorithm | Unknown key prefix | registration_malformed | PR1 |
| R37 | registration/1 | Key encoding | Key has padded base64url | registration_malformed | PR1 |
| R38 | registration/1 | Key confusion | Ed25519 raw key relabeled p256 (32 decoded bytes) | registration_signature_invalid | PR2 |
| R39 | registration/1 | P-256 point | SEC1 uncompressed point with recognized prefix | registration_signature_invalid | PR2 |
| R40 | registration/1 | P-256 point | 33 bytes with prefix 04 | registration_signature_invalid | PR2 |
| R41 | registration/1 | P-256 point | Compressed point with x at field prime | registration_signature_invalid | PR2 |
| R42 | registration/1 | P-256 point | Compressed x has no curve square root | registration_signature_invalid | PR2 |
| R43 | registration/1 | P-256 scalar r | Raw r=0 with valid in-range low s | registration_signature_invalid | PR2 |
| R44 | registration/1 | P-256 scalar r | Raw r=n with valid in-range low s | registration_signature_invalid | PR2 |
| R45 | registration/1 | P-256 scalar s | Raw s=0 with valid r | registration_signature_invalid | PR2 |
| R46 | registration/1 | P-256 scalar s | Raw s=n with valid r | registration_signature_invalid | PR2 |
| R47 | registration/1 | P-256 high-S | Valid ECDSA transformed to high-S twin | signature_high_s | PR2 |
| R48 | registration/1 | P-256 raw format | DER-encoded signature of exactly 70 decoded bytes, not 64 | registration_malformed | PR2 |
| R49 | registration/1 | P-256 equation | In-range low-S scalars fail the equation | registration_signature_invalid | PR2 |
| R50 | registration/1 | Ed25519 scalar | S at group order L | registration_signature_invalid | PR1 |
| R51 | registration/1 | Ed25519 weak key | Identity public key | registration_signature_invalid | PR1 |
| R52 | registration/1 | Ed25519 weak key | Nonidentity small-order public key | registration_signature_invalid | PR1 |
| R53 | registration/1 | Ed25519 subgroup | Mixed-order public key | registration_signature_invalid | PR1 |
| R54 | registration/1 | Ed25519 canonical point | Noncanonical public-point encoding | registration_signature_invalid | PR1 |
| R55 | registration/1 | Ed25519 R | Small-order signature R | registration_signature_invalid | PR1 |
| R56 | registration/1 | Ed25519 equation | Canonical points/scalar with invalid equation | registration_signature_invalid | PR1 |
| R57 | registration/1 | Nonce size | Nonce decodes to 15 bytes | registration_malformed | PR1 |
| R58 | registration/1 | Nonce canonicality | Nonce with nonzero unused trailing bits | registration_malformed | PR1 |
| R59 | registration/1 | Lifetime maximum | exp - iat = 121 seconds | registration_malformed | PR3 |
| R60 | registration/1 | Lifetime positivity | exp = iat | registration_malformed | PR4 |
| R61 | registration/1 | Lifetime ordering | exp before iat | registration_malformed | PR4 |
| R62 | registration/1 | Key enrollment | Correctly signed key absent from current records | key_not_enrolled | PR1 |
| R63 | registration/1 | Key currentness | Key appears only in historical record | key_not_enrolled | PR1 |
| R64 | registration/1 | Key window lower edge | iat one second before not_before | key_not_valid_now | PR5 |
| R65 | registration/1 | Key window upper edge | iat = not_after while now is inside | key_not_valid_now | PR6 |
| R66 | registration/1 | Key window current time | now = not_after while iat is inside | key_not_valid_now | PR6 |
| R67 | registration/1 | Host revocation | Current host is revoked; key/time valid | host_revoked | PR1 |
| R68 | registration/1 | Name syntax | Uppercase localpart | name_invalid | PR1 |
| R69 | registration/1 | Name syntax | Non-ASCII localpart | name_invalid | PR1 |
| R70 | registration/1 | Name syntax | Name contains @ or colon (one @ witness) | name_invalid | PR1 |
| R71 | registration/1 | Name syntax | Empty name | name_invalid | PR1 |
| R72 | registration/1 | Mxid size | Full mxid is 256 bytes | name_invalid | PR7 |
| R73 | registration/1 | Name authority | Valid structured name for host-b | name_not_permitted | PR1 |
| R74 | registration/1 | Prefix is not grammar | Prefix matches but name has an extra underscore | name_not_permitted | PR1 |
| R75 | registration/1 | Legacy exact match | Legacy name differs by one permitted character | name_not_permitted | PR8 |
| R76 | registration/1 | Audience exactness | Audience differs in DNS case | audience_mismatch | PR1 |
| R77 | registration/1 | Audience exactness | Audience is an HTTPS URL | audience_mismatch | PR1 |
| R78 | registration/1 | Restart barrier | iat one second below start_barrier | clock_skew | PR9 |
| R79 | registration/1 | Clock health | Backward UTC step detected | clock_skew | PR1 |
| R80 | registration/1 | Clock health | Synchronization health unavailable | clock_skew | PR1 |
| R81 | registration/1 | Future skew edge | iat = now + 31 seconds | request_not_yet_valid | PR10 |
| R82 | registration/1 | Expiration edge | now = exp + 30 seconds | request_expired | PR11 |
| R83 | registration/1 | Nonce replay | Same key/nonce already consumed | nonce_replayed | PR1 |
| R84 | registration/1 | Nonce scope | Same key/nonce with new body and valid signature | nonce_replayed | PR1 |
| R85 | registration/1 | Concurrent nonce | Second concurrent reservation of same pair | nonce_replayed | PR12 |
| R86 | registration/1 | Key limiter | 11th distinct-name attempt for key within 60 seconds | rate_limited | PR13 |
| R87 | registration/1 | Name limiter | 4th attempt for same name within 60 seconds | rate_limited | PR14 |
| R88 | registration/1 | Failed attempt counts | Two accepted seed attempts, replay debits third event, following fresh attempt exceeds name budget (Appendix A) | rate_limited | PR14 |
| R89 | registration/1 | Transport size | 65,537 received bytes with missing Content-Length | request_too_large | PR15 |
| R90 | registration/1 | Content type | text/plain with valid JSON body | unsupported_media_type | PR1 |
| R91 | registration/1 | Content encoding | gzip encoding | unsupported_media_type | PR1 |
| R92 | registration/1 | Routing path | Valid proof sent to unknown endpoint | endpoint_not_found | PR1 |
| R93 | registration/1 | Routing method | GET on registration endpoint | method_not_allowed | PR1 |
| R94 | registration/1 | Registry unavailable | Configured registry is unreadable | registry_unavailable | PR1 |
| R95 | registration/1 | Signer failure | Signing key unavailable after reservation | service_unavailable | PR1 |
| R96 | registration/1 | Audit sink failure | Off-host acknowledgement unavailable | audit_unavailable | PR16 |
| R97 | registration/1 | Audit local failure | Local append fails; readiness must close | audit_unavailable | PR16 |
| R98 | registration/1 | Final authority check | Host revoked between initial check and issuance | host_revoked | PR1 |
| R99 | registration/1 | Failure consumes nonce | Signing failed, then same proof retried with healthy signer | nonce_replayed | PR1 |
| R100 | registration/1 | Precedence malformed/id | Duplicate member and wrong id | registration_malformed | PR1 |
| R101 | registration/1 | Precedence id/signature | Wrong id and invalid equation | registration_id_mismatch | PR1 |
| R102 | registration/1 | Precedence high-S/enrollment | High-S request uses an unenrolled key | signature_high_s | PR2 |
| R103 | registration/1 | Precedence key/state | Expired key on revoked host | key_not_valid_now | PR1 |
| R104 | registration/1 | Precedence name/audience | Invalid name and wrong audience | name_invalid | PR1 |
| R105 | registration/1 | Precedence rate/replay | Budget exhausted and nonce already consumed | rate_limited | PR1 |
| R106 | registration/1 | Audit override | Id mismatch plus refusal-audit append failure | audit_unavailable | PR16 |
| R107 | registration/1 | Ed25519 R canonicality | Noncanonical encoding of R | registration_signature_invalid | PR1 |
| R108 | registration/1 | Ed25519 R subgroup | Mixed-order nonidentity R | registration_signature_invalid | PR1 |
| R109 | registration/1 | P-256 identity | SEC1 infinity encoding with p256 prefix | registration_signature_invalid | PR2 |
| R110 | registration/1 | Key window now lower edge | now one second before not_before, valid iat | key_not_valid_now | PR5 |
| R111 | registration/1 | Limiter rejection no debit | Rate refusal must not extend next release time | rate_limited; no debit | PR13 |
| R112 | registration/1 | Audit confidentiality | Faulted request contains token-like arbitrary data | registration_malformed; no raw log data | PR16 |
| E32 | enrollment/1 | Enrollment id | One valid id hex digit changed | enrollment_id_mismatch | PE1 |
| E33 | enrollment/1 | Publisher signature | Signature valid only under an unpinned publisher | enrollment_signature_invalid | PE1 |
| E34 | enrollment/1 | Envelope authority | Valid host signature used as publisher signature | enrollment_signature_invalid | PE1 |
| E35 | enrollment/1 | Domain separation | Sign registration domain, retain correct enrollment id | enrollment_signature_invalid | PE1 |
| E36 | enrollment/1 | Reserved sigs | Body carries sigs=[] | enrollment_sigs_unsupported | PE1 |
| E37 | enrollment/1 | Reserved sigs | Body carries sigs=null | enrollment_sigs_unsupported | PE1 |
| E38 | enrollment/1 | Host syntax | Host includes underscore | enrollment_malformed | PE1 |
| E39 | enrollment/1 | Host length | 33-character host label | enrollment_malformed | PE1 |
| E40 | enrollment/1 | Prefix equality | Prefix is not host plus underscore | enrollment_malformed | PE1 |
| E41 | enrollment/1 | Key list lower bound | Empty keys array | enrollment_malformed | PE1 |
| E42 | enrollment/1 | Key list upper bound | 17 key entries | enrollment_malformed | PE1 |
| E43 | enrollment/1 | Duplicate key | Same key repeated with disjoint windows | enrollment_malformed | PE1 |
| E44 | enrollment/1 | Key encoding confusion | Ed25519 key relabeled p256 | enrollment_malformed | PE2 |
| E45 | enrollment/1 | Window positivity | not_after = not_before | enrollment_malformed | PE1 |
| E46 | enrollment/1 | Window ordering | not_after before not_before | enrollment_malformed | PE1 |
| E47 | enrollment/1 | Nested schema | Unknown member in a key entry | enrollment_malformed | PE1 |
| E48 | enrollment/1 | Explicit duplicates | Identical explicit names repeated | enrollment_malformed | PE1 |
| E49 | enrollment/1 | Explicit syntax | Explicit name contains slash | enrollment_malformed | PE1 |
| E50 | enrollment/1 | UID presence P2 | Station host lacks uid_map | enrollment_malformed | PE1 |
| E51 | enrollment/1 | UID type | uid is string 1001 | enrollment_malformed | PE1 |
| E52 | enrollment/1 | UID range lower | uid=0 | enrollment_malformed | PE1 |
| E53 | enrollment/1 | UID range upper | uid=4294967295 | enrollment_malformed | PE1 |
| E54 | enrollment/1 | UID range sign | uid=-1 | enrollment_malformed | PE1 |
| E55 | enrollment/1 | UID duplicate | Same uid appears twice | enrollment_malformed | PE1 |
| E56 | enrollment/1 | UID permitted names | uid_map includes host-b name | enrollment_malformed | PE1 |
| E57 | enrollment/1 | UID empty names | uid_map names=[] | enrollment_malformed | PE1 |
| E58 | enrollment/1 | UID patterns | uid_map names contains wildcard | enrollment_malformed | PE1 |
| E59 | enrollment/1 | UID cross-assignment | Two UIDs claim same permitted name | enrollment_malformed | PE1 |
| E60 | enrollment/1 | Executable absolute | exe is relative path | enrollment_malformed | PE3 |
| E61 | enrollment/1 | Executable components | exe includes .. component | enrollment_malformed | PE3 |
| E62 | enrollment/1 | Executable components | exe includes repeated slash | enrollment_malformed | PE3 |
| E63 | enrollment/1 | Executable controls | exe contains NUL | enrollment_malformed | PE3 |
| E64 | enrollment/1 | Executable bound | exe is 4097 UTF-8 bytes | enrollment_malformed | PE3 |
| E65 | enrollment/1 | UID schema | Unknown member in uid_map entry | enrollment_malformed | PE1 |
| E66 | enrollment/1 | Sequence lower bound | seq=0 | enrollment_malformed | PE1 |
| E67 | enrollment/1 | Sequence type | seq is a numeric string | enrollment_malformed | PE1 |
| E68 | enrollment/1 | State vocabulary | state=disabled | enrollment_malformed | PE1 |
| E69 | enrollment/1 | Duplicate host position | Two envelopes at same host,seq, even identical | registry_conflict | PE4 |
| E70 | enrollment/1 | Cross-host key | Two hosts claim same decoded key | registry_conflict | PE4 |
| E71 | enrollment/1 | Cross-host legacy name | Two hosts explicitly claim same legacy name | registry_conflict | PE4 |
| E72 | enrollment/1 | Cross-host structured name | Explicit list borrows another host structured name | registry_conflict | PE4 |
| E73 | enrollment/1 | Tombstone permanence | Active record after revoked record | registry_rollback | PE5 |
| E74 | enrollment/1 | Sequence rollback | Pin lowers current host seq | registry_rollback | PE6 |
| E75 | enrollment/1 | Sequence equivocation | Same seq has a changed body id | registry_rollback | PE6 |
| E76 | enrollment/1 | History omission | Candidate drops an acknowledged tombstone/host | registry_rollback | PE6 |
| E77 | enrollment/1 | Revision rollback | Candidate pin is ancestor of accepted revision | registry_rollback | PE6 |
| E78 | enrollment/1 | Commit trust | Pinned commit has an invalid or unapproved signer | registry_unavailable | PE1 |
| E79 | enrollment/1 | Commit pin | Mutable branch used instead of exact object id | registry_unavailable | PE1 |
| E80 | enrollment/1 | Snapshot atomicity | One malformed high-seq record beside valid older record | enrollment_malformed; no fallback | PE4 |
| E81 | enrollment/1 | Restore freshness | High-water evidence lost after restoration | registry_unavailable; admission fenced | PE6 |
| E82 | enrollment/1 | Enrollment byte cap | Envelope file is 65,537 bytes | enrollment_malformed | PE1 |
| E83 | enrollment/1 | Executable components | exe contains . component | enrollment_malformed | PE3 |
| E84 | enrollment/1 | Executable components | exe has trailing slash | enrollment_malformed | PE3 |
| E85 | enrollment/1 | Executable components | exe is root path alone | enrollment_malformed | PE3 |
| E86 | enrollment/1 | UID name duplicates | One UID repeats a permitted name | enrollment_malformed | PE1 |
| E87 | enrollment/1 | Enrollment strict Ed25519 | Publisher signature has S at L | enrollment_signature_invalid | PE1 |
| E88 | enrollment/1 | Registry filesystem | Enrollment entry is a symlink | registry_unavailable | PE1 |
| E89 | enrollment/1 | Snapshot cap | 10,001 envelopes | registry_unavailable | PE4 |
| E90 | enrollment/1 | Station classification | Required station-host classification missing | registry_unavailable | PE1 |
| R114 | registration/1 | Content-type parameters | application/json with an unsupported parameter | unsupported_media_type | PR1 |
| R115 | registration/1 | Nonce alphabet | Nonce uses standard base64 slash | registration_malformed | PR1 |
| R116 | registration/1 | ASCII audience | aud contains non-ASCII | registration_malformed | PR1 |
| R117 | registration/1 | Unknown nested sig | Body has an extra sig member | registration_malformed | PR1 |
| R118 | registration/1 | Timestamp width | Month lacks zero-padding | registration_malformed | PR1 |
| R119 | registration/1 | Timestamp offset | Timestamp omits zone | registration_malformed | PR1 |
| R120 | registration/1 | Signature size upper | Signature decodes to 65 bytes | registration_malformed | PR1 |
| R121 | registration/1 | Body/signature binding | Body name changed without resigning; id recomputed | registration_signature_invalid | PR1 |
| R122 | registration/1 | Final expiry check | Clock passes exp+30 during signing | request_expired | PR11 |
| E91 | enrollment/1 | UID map size lower | uid_map=[] | enrollment_malformed | PE1 |
| E92 | enrollment/1 | UID map size upper | 257 unique UID entries | enrollment_malformed | PE1 |
| E93 | enrollment/1 | UID names size upper | 65 permitted names in one entry | enrollment_malformed | PE1 |
| E94 | enrollment/1 | Explicit list bound | 257 distinct valid explicit names | enrollment_malformed | PE1 |
| E95 | enrollment/1 | Host syntax case | Uppercase host label | enrollment_malformed | PE1 |
| E96 | enrollment/1 | Host size lower | Empty host label | enrollment_malformed | PE1 |
| E97 | enrollment/1 | Names nested schema | Unknown member in names object | enrollment_malformed | PE1 |
| E98 | enrollment/1 | Executable byte grammar | exe contains backslash | enrollment_malformed | PE3 |
| E99 | enrollment/1 | Executable control grammar | exe contains a newline | enrollment_malformed | PE3 |
| E100 | enrollment/1 | Explicit mxid size | An explicit name makes a 256-byte mxid | enrollment_malformed | PE1 |
| E101 | enrollment/1 | Historical key non-reassignment | A revoked host key is moved to another host | registry_conflict | PE5 |
| E102 | enrollment/1 | Registry byte cap | Aggregate envelope bytes exceed 16 MiB | registry_unavailable | PE4 |
| E103 | enrollment/1 | High-water persistence | Candidate persistence fails before installation | registry_unavailable; no new authority | PE6 |
| E104 | enrollment/1 | Failed reload fences old cache | New pin invalid while prior cache remains readable | registry_unavailable; old cache not usable | PE6 |
| E105 | enrollment/1 | Publisher pin missing | No configured offline publisher public key | registry_unavailable | PE1 |
| E106 | enrollment/1 | Reserved sigs precedence | sigs=[] plus body schema violation | enrollment_sigs_unsupported | PE1 |
| R123 | registration/1 | Final post-audit revalidation | Registry changes to revoked while sink acknowledgement is in flight | host_revoked; no JWT released | PR16 |
| R124 | registration/1 | Future-skew-across-restart regression | Prior process accepted iat=90, exp=210 at now=60; restart at 61.2, empty cache, identical proof replayed at now=62; barrier=92 | clock_skew | PR22 |
| R125 | registration/1 | Restart adjacent lower edge | Prior process accepted iat=91, exp=211 at now=61 before restart 61.2; new barrier=92, replay at now=62 with iat=barrier-1 | clock_skew | PR22 |
| R126 | registration/1 | Restart initial partial second | Restart at 61.2; fresh proof iat=92, exp=212 equals barrier, but registrar now=61 still permits only iat<=91 | request_not_yet_valid | PR22 |
| R127 | registration/1 | Restart waiting does not rehabilitate proof | Replay R124 unchanged at now=92 after waiting; fixed barrier still 92 and old iat still 90 | clock_skew | PR23 |
| R128 | registration/1 | Pending-token key cutover | Sign at generation A; await audit; switch active generation to B; acknowledge audit; final release sees mismatch | service_unavailable; no JWT; reserved nonce retained | PR26 |
| R129 | registration/1 | Lowered positive rate capacity | Configured key/name capacities both 1; second fresh attempt in 60-second window | rate_limited; no second debit/reservation | PR25 |
| R130 | registration/1 | `test_clock_recovery_does_not_reenable_pre_restart_proof` | A starts at 0 and accepts iat=90, exp=210 at now=60; UTC regresses, B starts at 31.2 with barrier=62 and fails startup clock health; restore synchronized UTC to 62 and attempt in-place reopening with the identical proof | clock_skew; B remains fenced; no JWT | PR27 |
| R131 | registration/1 | Recovery still fenced without restart | Continue R130 in B at now=93 with a fresh iat=93, exp=213 and nonce; current clock is healthy but B's process-lifetime fence remains | clock_skew; no JWT | PR27 |
| R132 | registration/1 | Restart after clock recovery rejects old proof | After R130, operator verifies synchronized UTC and restarts at 62.2; new process passes its startup check, barrier=93; replay A's identical iat=90, exp=210 proof at now=93 | clock_skew; no JWT | PR27 |
| R133 | registration/1 | Healthy-start process cannot clear a later clock fence | Process starts with verified healthy UTC at 0, then loses synchronization and trips its clock fence; restore verified synchronization at now=60 and offer fresh iat=60, exp=180 and nonce without restart | clock_skew; process remains fenced; no JWT | PR27 |
| E107 | enrollment/1 | Loader snapshot-wide phases | a.json has bad publisher signature; z.json has reserved sigs; all phase-1 shapes valid | enrollment_sigs_unsupported | PE1 |
| E108 | enrollment/1 | Loader path-order independence | a.json has reserved sigs; z.json has bad publisher signature; all phase-1 shapes valid | enrollment_sigs_unsupported | PE1 |
| E109 | enrollment/1 | Loader parse-before-reserved phase | a.json has reserved sigs; z.json has duplicate JSON member | enrollment_malformed | PE1 |
| E110 | enrollment/1 | Conflict-before-rollback precedence | Candidate contains a cross-host duplicate key and lowers an acknowledged host sequence | registry_conflict | PE6 |
| E111 | enrollment/1 | Legacy-name historical non-transfer | Host removes legacy.dev in a higher sequence; another host claims it while original history remains | registry_conflict | PE13 |
| R134 | registration/1 | Leading-hyphen structured mxid upper neighbor | PR29 with signed request name `-node_project_rolex`: 256-byte mxid, valid structured grammar and matching long audience | name_invalid; no reservation or debit | PR29 |
| R135 | registration/1 | Leading-hyphen malformed structured name | PR28 with signed request name `-node_p_`: missing role, also outside legacy grammar; valid matching enrollment unchanged | name_invalid; no reservation or debit | PR28 |
| R136 | registration/1 | Media type token boundary | Content-Type `app lication/json`; otherwise PR1 | unsupported_media_type; no reservation or debit | PR1 |
| R137 | registration/1 | Media subtype token boundary | Content-Type `application/j son`; otherwise PR1 | unsupported_media_type; no reservation or debit | PR1 |
| R138 | registration/1 | Unquoted charset requirement | Content-Type `application/json;charset="utf-8"`; otherwise PR31 | unsupported_media_type; no reservation or debit | PR31 |
| R139 | registration/1 | Charset equals boundary | Content-Type `application/json;charset = utf-8`; otherwise PR31 | unsupported_media_type; no reservation or debit | PR31 |
| E112 | enrollment/1 | Leading-hyphen structured UID mxid upper neighbor | PE15 with UID-map name `-node_project_rolex`: 256-byte mxid, valid structured grammar; explicit `legacy.dev` still fits | enrollment_malformed | PE15 |
| E113 | enrollment/1 | Leading-hyphen explicit entry remains legacy-only | PE14 with additional explicit entry `-node_project_role`; same valid structured UID name, but explicit entry fails legacy grammar | enrollment_malformed | PE14 |
| E114 | enrollment/1 | Leading-hyphen malformed structured UID name | PE14 with UID-map name `-node_p_`: missing role, also outside legacy grammar | enrollment_malformed | PE14 |
| PR1 | registration/1 | Ordinary Ed25519 admission and exact seven-member body | None | accept | PR1 |
| PR2 | registration/1 | Valid compressed P-256 and raw low-S signature | None | accept | PR2 |
| PR3 | registration/1 | Proof lifetime exactly 120 seconds | None | accept | PR1 |
| PR4 | registration/1 | Proof lifetime one second | None | accept | PR1 |
| PR5 | registration/1 | iat and now equal not_before | None | accept | PR1 |
| PR6 | registration/1 | iat and now one second below not_after | None | accept | PR1 |
| PR7 | registration/1 | Explicit legacy name makes mxid exactly 255 bytes | None | accept | PR8 |
| PR8 | registration/1 | Exact legacy explicit name legacy.dev | None | accept | PR1 |
| PR9 | registration/1 | iat equals start_barrier after restart | None | accept | PR1 |
| PR10 | registration/1 | iat equals now + 30 seconds | None | accept | PR1 |
| PR11 | registration/1 | now equals proof exp + 29 seconds | None | accept | PR1 |
| PR12 | registration/1 | First of concurrent duplicate reservations | None | accept once; one JWT total | PR1 |
| PR13 | registration/1 | 11th key attempt after oldest event reaches 60 seconds | None | accept; independent names below cap | PR1 |
| PR14 | registration/1 | Third same-name attempt in window with fresh nonce | None | accept | PR1 |
| PR15 | registration/1 | 65,536-byte envelope using insignificant whitespace | None | accept | PR1 |
| PR16 | registration/1 | Audit chain with off-host acknowledgement | None | accept; exact fields, no JWT in log | PR1 |
| PR17 | registration/1 | JWT header/claims and canonical JWS bytes | None | accept; nbf=iat, exp=iat+120, no kid | PR1 |
| PR18 | registration/1 | Same nonce on another enrolled key | None | accept | PR2 |
| PR19 | registration/1 | Name includes optional qualifier | None | accept | PR1 |
| PR20 | registration/1 | Wire whitespace/order/escaped ASCII differ, values unchanged | None | accept; same id and preimage | PR1 |
| PR21 | registration/1 | Proof window does not constrain JWT expiry | Proof lifetime one second | accept; JWT lifetime remains 120 seconds | PR4 |
| PE1 | enrollment/1 | Valid station enrollment plus pinned publisher and commit | None | accept | PE1 |
| PE2 | enrollment/1 | P-256 host key in enrollment, Ed25519 publisher signature | None | accept | PE1 |
| PE3 | enrollment/1 | UID entry with exact path /usr/bin/client | None | accept | PE1 |
| PE4 | enrollment/1 | History contains distinct host sequences and two hosts | None | accept; highest seq selected | PE1 |
| PE5 | enrollment/1 | Higher-sequence revoked record retaining history | None | accept registry; host stays revoked | PE1 |
| PE6 | enrollment/1 | Descendant pin advances seq and persists high-water | None | accept | PE1 |
| PE7 | enrollment/1 | Two distinct keys overlap for rotation | None | accept; either valid key usable | PE2 |
| PE8 | enrollment/1 | Confirmed nonstation host omits uid_map | None | accept | PE1 |
| PE9 | enrollment/1 | Publisher pin rotation re-signs unchanged bodies | None | accept; ids/high-water unchanged | PE6 |
| PE10 | enrollment/1 | UID maximum 4294967294 | None | accept | PE1 |
| PE11 | enrollment/1 | Host label lengths 1 and 32 (32-byte witness) | None | accept | PE1 |
| PE12 | enrollment/1 | Sequence at safe integer maximum | None | accept | PE1 |
| PR22 | registration/1 | Fresh restart-barrier proof with maximum future skew | Restart=61.2, barrier=92, now=62, fresh iat=92, exp=212 and nonce | accept | PR1 |
| PR23 | registration/1 | Fresh synchronized proof after startup hold | Restart=61.2, barrier=92, now=92, fresh iat=92, exp=212 and nonce | accept | PR1 |
| PR24 | registration/1 | Restart adjacent upper edge | Restart=61.2, barrier=92, now=92, fresh iat=93, exp=213 and nonce | accept | PR1 |
| PR25 | registration/1 | Minimum positive limiter capacity | Configure key/name capacities both 1, empty windows/cache, first valid proof | accept; one debit per budget and one nonce | PR1 |
| PR26 | registration/1 | Pending token without key cutover | Sign at generation A, audit waits and acknowledges, active generation remains A and unpaused | accept; one JWT released | PR16 |
| PR27 | registration/1 | Fresh proof at recovered restart barrier | Continue R132 in the new verified-start process, barrier=93, now=93, fresh iat=93, exp=213 and nonce | accept; one debit per budget and one nonce; one JWT | PR1 |
| PE13 | enrollment/1 | Same-host historical legacy name | One active host removes then re-adds its legacy.dev at higher sequences, all retained | accept; no cross-host ownership change | PE1 |
| PR28 | registration/1 | Leading-hyphen structured request host | Valid signed request for `-node_project_role`, host `-node`, matching enrollment and default audience | accept | PR1 |
| PR29 | registration/1 | Leading-hyphen structured request at mxid cap | PR28 with the configured 235-byte audience above; `-node_project_role` makes the mxid exactly 255 bytes | accept | PR28 |
| PR30 | registration/1 | Permitted case-insensitive charset tokens | PR1 with Content-Type `Application/JSON;Charset=UtF-8`, with no whitespace ambiguity | accept | PR1 |
| PR31 | registration/1 | Unquoted charset control | PR1 with Content-Type `application/json;charset=utf-8` | accept | PR1 |
| PR32 | registration/1 | Charset separator OWS | PR31 with Content-Type `application/json ;\tcharset=utf-8`, where `\t` denotes HTAB | accept | PR31 |
| PR33 | registration/1 | Complete field-value OWS | PR31 with Content-Type ` \tapplication/json;charset=utf-8\t `, where `\t` denotes HTAB | accept | PR31 |
| PE14 | enrollment/1 | Leading-hyphen structured UID name | Valid publisher-signed station enrollment for host `-node`, prefix `-node_`, UID-map name `-node_project_role`, default audience | accept | PE1 |
| PE15 | enrollment/1 | Leading-hyphen structured UID name at mxid cap | PE14 with the configured 235-byte audience above; UID-map name `-node_project_role` makes the mxid exactly 255 bytes | accept | PE14 |
| PC1 | enrollment/1 | CCJ codec: Object order | Keys include a supplementary scalar and a BMP scalar; sort by scalar, not UTF-16 code unit | accept (codec) | PC1 |
| PC2 | enrollment/1 | CCJ codec: Whitespace | No insignificant whitespace in canonical output | accept (codec) | PC2 |
| PC3 | enrollment/1 | CCJ codec: Array order | Distinct array values retain input order | accept (codec) | PC3 |
| PC4 | enrollment/1 | CCJ codec: String escapes | All short control escapes plus another C0 control use exact CCJ spelling | accept (codec) | PC4 |
| PC5 | enrollment/1 | CCJ codec: Literal Unicode | Slash, angle brackets, ampersand and non-ASCII stay unescaped | accept (codec) | PC5 |
| PC6 | enrollment/1 | CCJ codec: Integer spelling | Safe integer endpoints and zero retain exact shortest decimal bytes | accept (codec) | PC6 |
| PC7 | enrollment/1 | CCJ codec: Literals | true, false and null retain lowercase spelling | accept (codec) | PC7 |
| PC8 | enrollment/1 | CCJ codec: Surrogate pair | Valid paired surrogate escapes become one UTF-8 scalar | accept (codec) | PC8 |
| PC9 | enrollment/1 | CCJ codec: Unicode normalization | Composed and decomposed strings produce distinct canonical bytes | accept (codec) | PC9 |
| PC10 | enrollment/1 | CCJ codec: Sig extraction | Top-level envelope sig excluded; nested sig not recursively stripped | accept (codec) | PC10 |

### B.1 Isolated integration qualification (normative plan)

After canonical and negative vectors, the next implementation stages MUST
qualify an isolated test homeserver. No live carrier login is authorized by
this plan. Integration cases are separate from the two-domain byte vectors:

| Id | Required observation | Negative control / limit |
| --- | --- | --- |
| I1 | First valid JWT login creates one account; second reaches the same mxid. | Invalid JWT signature creates no account. |
| I2 | Closed registration rejects a formerly valid registration token. | Qualified JWT provisioning remains available. |
| I3 | Revocation fences helper and registrar, and logout ends existing devices. | Outstanding JWT cannot regain usable access under qualified lock/expiry procedure. |
| I4 | Required JWT issuer, audience, exp and nbf checks apply. | Missing/wrong claims refuse; valid one-audience token passes. |
| I5 | Allowed alg is EdDSA with configured Ed25519 public PEM. | HS256/none and mismatched key refuse; typ/kid are not assumed server gates. |
| I6 | Homeserver exp+60 and nbf-60 equality boundaries match inspected version. | exp+61 and nbf-61 refuse; a modified version records its own exact bounds. |
| I7 | The qualified reviewed homeserver change issues 86,400-second access tokens without refresh tokens. | Stock v1.9.3 no-refresh login is an expected unsupported control, never a green expiry claim. |
| I8 | Coordinated registrar/homeserver key switch admits only current signatures. | Old signature refuses after switch; existing access tokens require separate logout. |
| I9 | CLI atomically persists exactly three credential fields with mode 0600. | JWT, password, refresh token and secret-bearing errors never reach file, stdout or logs. |
| I11 | Keymaker refuses a wrong audience before producing a proof. | Correct configured audience and permitted name produce a registrar-verifiable proof; refusal name belongs to Keymaker. |
| I12 | Keymaker obtains caller UID from the kernel and enforces uid_map. | Foreign UID, false executable evidence and unsupported peer credentials refuse under its own contract. |
| I10 | Restart refuses the previously accepted +30-second-future proof with an empty nonce cache. | Fresh proof at/after the skew-covering barrier passes; waiting never rehabilitates the old proof. |
| I13 | `second_login_has_same_mxid`: repeat the identical JWT under the pinned state below; assert `(second.status, second.user_id) == (200, first.user_id)`. | A signature-corrupted token is the separate invalid-token control from I1; no single-use jti guarantee is claimed. |
| I14 | Configured limiter capacities of zero prevent admission startup as a configuration error. | Capacities of 1 start successfully and follow PR25/R129; no infinite Retry-After is issued. |
| I15 | The qualified reviewed homeserver change refuses an otherwise valid JWT login for a deactivated account. | The same valid JWT for that account while active and unlocked succeeds; the deactivated-account refusal creates no device or access token. |

I13 replaces the former R113 homeserver-replay row; it is an integration
assertion, not a two-domain format verdict. Pin the homeserver to the §10.2
commit and operator JWT configuration, one unchanged registrar verification
key, an existing active/unlocked JWT-origin account, healthy audit/clock and
unchanged issuer/audience. The JWT has `iat=now`, `nbf=iat`, `exp=iat+120` and a
fixed `jti`. Sequentially log in at `iat+1` and `iat+2`, with the identical JWT,
no refresh request, and distinct device identifiers. Test-server limiter
configuration/counters MUST allow both logins; there are no concurrent lock,
account or key changes. The first 200 login is setup. The sole named replay
assertion is `second_login_has_same_mxid` from the row; service/runtime failures
are unrun qualification, never an alternative expected outcome.

A future test harness MUST demonstrate that its refusal/side-effect checker
fails on a bounded deliberate bypass (for example a nonce-check bypass producing
a second JWT). A crash or an unrelated setup failure is not that control.
These are planned gates, not passing implementation evidence.

### B.2 External-witness lifecycle (normative plan; no fixtures yet)

These 37 additional rows plan §4.5 state transitions. W/PW identifiers are
separate from the 310 byte-vector rows above; no witness fixture or executable
conformance is claimed. Each case starts with a valid signed registry and
protected configuration. Unless changed below, local state L and latest durable
witness resolved-commit state L have equal digest/revision at sequence n, with
trusted continuity and fresh authenticated replies. Only one consumer instance
may serve. Unless changed below, a successful replacement writes intent n+1,
commits locally, then writes matching committed resolution n+2.

Each future fixture MUST distinguish local durable high-water, usable authority,
witness head/receipt and readiness. Admission accounting MUST remain unchanged;
these are loader/startup operations, not admission requests. Record/ack traces
MUST be exact. W rows MUST assert the intended fence and lack of new signing/
issuance, not merely an error. Intent failure leaves local high-water unchanged.
Commit-success/resolution-failure rows retain the new local state and external
unresolved-intent fence, unlike validation refusals in Appendix A.
No witness operation may weaken history, ownership, tombstones or protected pins.

| Id | Rule | Defect / boundary | Expected result | Positive control |
| --- | --- | --- | --- | --- |
| W1 | Startup equality | Restore local L while the fresh latest witness records newer M | registry_unavailable; local L unchanged; no reconciliation | PW1 |
| W2 | Unresolved local advance | Intent for M is acknowledged; commit M succeeds but resolving append is not durable | registry_unavailable; M retained, latest intent unresolved, fenced | PW2 |
| W3 | Missing local evidence | Witness L survives but local high-water is missing | registry_unavailable; no implicit bootstrap or state reconstruction from a digest | PW1 |
| W4 | Missing witness evidence | Valid local L but stream has no record | registry_unavailable; no implicit first use | PW1 |
| W5 | Witness unavailable at start | Read is unreachable or exceeds its finite deadline | registry_unavailable; no automatic reconciliation | PW1 |
| W6 | Replayed stale view | Replay L's authentic old receipt/reply against a new lookup challenge while authoritative head is M | registry_unavailable; stale reply is not latest evidence | PW1 |
| W7 | Protected binding | Reply/receipt belongs to another stream or unauthenticated witness | registry_unavailable; no stream replacement or reconciliation | PW1 |
| W8 | Exact resolving acknowledgement | Intent acknowledged and commit M succeeds; resolving receipt changes the final digest/hash byte, revision or intent hash | registry_unavailable; M durable, resolution unproven, authority fenced; no rollback | PW2 |
| W9 | Lost resolving acknowledgement | Intent acknowledged and commit M succeeds; resolving append/ack is unknown and no fresh latest-head confirmation is obtainable | registry_unavailable; M durable, resolution unproven, fenced | PW3 |
| W10 | Witness rollback | Fresh head sequence n-1 is below independently surviving trusted n | registry_unavailable; backwards head is not adopted | PW4 |
| W11 | Witness equivocation | Fresh record differs at the trusted sequence n, even if its state digest matches | registry_unavailable; same-sequence replacement is not adopted | PW4 |
| W12 | Continuity | Fresh head advances but its chain cannot extend trusted n | registry_unavailable; no reset/truncation of the accepted chain | PW4 |
| W13 | Release ordering | Intent acknowledged and Store.Commit(M) succeeds; attempt authority use before resolving acknowledgement | registry_unavailable; neither old L nor pending M may authorize signing | PW2 |
| W14 | Local commit error | Intent acknowledged; Store.Commit reports failure, including ambiguous durability | registry_unavailable; intent unresolved; no resolving append or snapshot use; option A required | PW5 |
| W15 | Old receipt at new commit | Intent acknowledged and commit M succeeds; replay L's resolved record at n in place of the new resolution | registry_unavailable; old record cannot resolve the new intent | PW2 |
| W16 | Concurrent intent append | Two intents compare the same previous resolved head; one intent is already durable | Losing different proposal is refused before Store.Commit; no duplicate sequence or losing authority release | PW6 |
| W17 | Split-brain prerequisite | A replacement cannot establish exclusion of an older serving instance | Replacement fenced before commit/use; a witness CAS alone is insufficient | PW6 |
| W18 | False option A evidence | Latest intent is unresolved; operator relies only on restored local bytes/receipt to confirm state or cancel/resolve the intent | No reconciliation or intent resolution; no signing/issuance; external intent retained | PW5 |
| W19 | Complete-state digest | Keep revision/current sequence fixed but change retained history, revoked flag, historical key owner or removed-name owner | Digest changes for each isolated mutation; old receipt cannot reconcile the changed state | PW2 |
| W20 | Every successful commit | Acknowledged intent for identical L; commit L succeeds but omit its committed resolution | Local L retained; external intent fences despite equal digest; old receipt is insufficient | PW8 |
| W21 | Explicit fallback | Witness becomes unreachable; automatically change to option A without operator reconciliation | registry_unavailable; no automatic downgrade | PW7 |
| W22 | Final local binding | After exact resolving receipt for M, local committed bytes or approved pin change before publication | registry_unavailable; receipt cannot authorize the different state/pin | PW2 |
| W23 | Sequence exhaustion | Last resolved sequence is 9007199254740990; insufficient space for both intent and resolution | Fence before intent or Store.Commit; never wrap, reset or switch streams | PW4 |
| W24 | Invalid digest preimage | Omit a map, substitute null, add an unknown field or use history-key alias 01 | No accepted digest/reconciliation; existing authority and witness head unchanged | PW1 |
| W25 | Remembered pending restart | Restart remembers an unchanged-state commit; latest durable head is its unresolved intent | Operator recovery required even though local digest equals the intent; no automatic resolution | PW3 |
| W26 | Whole-host restore after changed-state commit | Acknowledge intent for M; commit M; resolution not durable; restore snapshot L with all local pending identity erased | Fresh latest intent survives; fence and require option A despite restored L matching the older resolved record | PW1, PW9 |
| W27 | Whole-host restore after unchanged-state commit | Acknowledge intent for L; commit L; resolution not durable; restore pre-intent snapshot with all local pending identity erased | Fresh latest intent survives; fence and require option A despite equal local/intent/older-resolved digests | PW1, PW9 |
| W28 | Intent failure before commit | Intent append or exact receipt fails, including no durability, lost receipt or wrong digest/hash | No Store.Commit or resolving append; local L unchanged; old authority fenced as failed reload; any durable intent survives | PW2 |
| PW1 | Fresh equal startup | Valid local L; fresh challenge-bound latest committed head resolves its intent for L with correct stream/continuity | Reconciled; no local mutation or witness append; ordinary registry validation still required | PE6 |
| PW2 | Witnessed replacement | Valid M; intent n+1 exactly acknowledged; Store.Commit(M) succeeds; matching committed n+2 exactly acknowledged; final bytes/pin match | M usable only after both acknowledgements in order; complete pair and local M retained | PE6 |
| PW3 | Lost-resolution-receipt recovery | Intent acknowledged; commit M succeeds; committed n+2 is durable but ack was lost; fresh latest read proves that exact resolution | Use M only after proof/final validation; no second append or unresolved intent | PW2 |
| PW4 | Monotonic advance | Trusted resolved n; intent n+1 and matching committed n+2 extend it exactly; final local state matches | Reconciled; preserve complete pair/continuity; no sequence reset | PW1 |
| PW5 | Operator intent recovery | Quiesce; fresh unresolved intent; operator independently authenticates and authorizes exact candidate/digest/revision/intent hash and surviving history evidence; recover/verify its durable commit and acknowledge matching resolution | Resolve only the exact intent; final validation before authority use; no local-only or automatic recovery | PW7 |
| PW6 | Serialized ownership | Prior instance excluded; sole consumer appends next expected intent, commits, then appends its resolution | One intent/resolution pair; only the reconciled instance serves | PW2 |
| PW7 | Manual fallback | Witness unavailable; operator verifies exact local digest/history against independent surviving evidence and explicitly selects option A | Option A reconciliation permits otherwise valid authority; every later start still needs reconciliation | PE6 |
| PW8 | Unchanged successful commit | Acknowledge new intent for identical L, commit L, then acknowledge its exact committed resolution | Exactly two new sequences; authority usable after resolution; exact retries append neither record twice | PW2 |
| PW9 | Resolved-commit restart | For each changed-state M and unchanged-state L case, complete both acknowledged records and restart with the exact resolved local state and no local pending marker | Latest head is matching committed resolution; reconcile after normal validation, distinguishing both W26/W27 restores and preserving PW1 | PW1 |

Future instrument controls MUST include admitting W13 before acknowledgement
and accepting W6's stale reply. They MUST also remove or move the intent after
Store.Commit and demonstrate failure of both W26 and W27 startup assertions.
Each control MUST fail its named assertion;
an unrelated setup failure is not a detected violation. Restore of both host
and witness with no independent surviving head is the explicit §4.5.3 limit,
not a negative test that can claim detection from equal hashes.

### B.3 Platform-time provider and startup lifecycle (normative plan; no fixtures yet)

These 33 plans are separate from the unchanged 310 byte rows, B.1 integration
plans and B.2 witness plans. T/PT ids do not add vector files or claim executable
startup qualification. Negative rows precede their resolving positive controls.
Use one serving instance, an excluded prior instance, otherwise valid registry,
proof, signer and audit, and independent true/UTC/monotonic readings. Record
provider source/config matching, tracking status, sample/expiry, delta_sample,
protected delta_cap, both check results, hold elapsed, fixed instant/barrier,
readiness and JWT count. Every clock refusal releases no JWT and leaves authority
unchanged. Startup refusals and row-15 refusals before reservation create no nonce
reservation or budget debit. A clock failure at row 20 after rows 18–19, or at
post-acknowledgement revalidation, MUST retain the consumed nonce and both limiter
debits; health loss, authority expiry and over-cap evidence all follow this rule.
Record the refusal as §9 requires; an already acknowledged issued audit line may
remain alongside the later refusal. Audit failure keeps its terminal override.
For T15/T16, start each subcase with empty accounting and one otherwise valid
fresh proof: at refusal, early cases leave (nonces, key debits, name debits)=(0,0,0),
while late cases retain (1,1,1). An already tripped process remains fenced after
subsequent healthy evidence.
Source-selection negatives do not claim authenticated per-source NTS observation.

| Id | Claim | Fixture / scheduled action | Expected result / forbidden outcome | Positive control |
| --- | --- | --- | --- | --- |
| T1 | Fast-restart ordering regression | Old UTC=1001.0 accepts iat=1031; new initial UTC=1000.3, delta_sample=0.5; exclude old instance, hold 4 monotonic seconds, fix at UTC=1004.3, barrier=1035; replay unchanged proof, including after waiting to UTC=1035 | clock_skew; no JWT, reservation or debit; waiting cannot rehabilitate iat=1031 | PT1 |
| T2 | `test_startup_hold_shorter_than_twice_delta_cap_fences` | Try to fix start after 2.9 monotonic seconds, less than 2*1.5=3, with healthy checks | Startup unqualified; no fixed serving barrier/readiness or JWT; this named test fails if the shortened hold serves | PT1 |
| T3 | Full one-second margin | Try to fix start after 3.5 monotonic seconds, above 2*delta_cap but below 4 | Startup unqualified; no admission; the margin cannot be rounded away | PT1 |
| T4 | New-sample-only delta regression | Old true=1000.70, UTC=1002.20, delta=1.5 accepts iat=1032; new launch true=1000.71, UTC=1000.61, delta=0.1; attempt hold=1.2 and fixed UTC=1001.81, barrier=1032 | Shortened startup cannot qualify; otherwise replay at new UTC=1002 would re-admit iat=1032. Production uses 4 seconds and refuses the old proof | PT3 |
| T5 | Provider unavailable at start | Initial provider check is unavailable; local UTC/healthy flag appears normal | Process-lifetime clock fence; no start qualification or JWT | PT1 |
| T6 | Selected source must match NTS config | Selected source matches no configured nts line by name or address, even if another line is nts | Provider unavailable; startup fenced | PT2 |
| T7 | Every configured source uses NTS | Selected source matches an nts line, but another configured source lacks nts | Provider unavailable; startup fenced | PT2 |
| T8 | Leap status | Tracking leap is not Normal | Startup clock fence | PT2 |
| T9 | Synchronization age | Last synchronization age is 2048.001 seconds at a startup check | Startup clock fence | PT2 |
| T10 | Offset magnitude bound | Offset is +0.5001 or -0.5001 seconds, with other fields healthy | Startup clock fence; signed cancellation cannot admit the negative case | PT2 |
| T11 | Root distance bound | Root distance is 1.0001 seconds, with other fields healthy | Startup clock fence | PT2 |
| T12 | Reported error cap | Provider reports delta_sample above 1.5, negative or not a finite error bound, despite a healthy status | Startup fenced; healthy boolean cannot bypass the common bound | PT2 |
| T13 | Protected policy cap | Configure delta_cap above 1.5 seconds | Startup configuration refused; no serving or JWT | PT1 |
| T14 | Fixed-instant second check | First check passes and hold completes; at the proposed fixed instant independently inject unavailable health, expired authority or delta_sample above cap | No valid fixed start; process-lifetime fence; no reuse of the first check | PT1 |
| T15 | Loss of provider health by stage | Independently inject unavailable health or delta_sample above cap: (a) during the startup hold, (b) at row 15 before reservation, (c) at row 20 after rows 18–19, (d) after the issued audit acknowledgement; then restore healthy evidence | No JWT; permanent clock fence. Cases (a,b): accounting (0,0,0); cases (c,d): retain (1,1,1). Request refusals record clock_skew with healthy audit; (d) keeps the acknowledged issued line and adds the refusal | PT4 |
| T16 | Authority expiry equality by stage | Independently reach sample age=300 with healthy status and no replacement: (a) startup recheck, (b) row 15 before reservation, (c) row-20 revalidation after rows 18–19 passed with unexpired authority, (d) post-ack revalidation after an unexpired issued acknowledgement | No JWT; permanent expiry fence. Cases (a,b): accounting (0,0,0); cases (c,d): retain (1,1,1). Request refusals record clock_skew with healthy audit; (d) retains the issued line plus refusal. Healthy status cannot extend authority | PT5 |
| T17 | Registrar stricter than shared step threshold | After healthy start, detect a -0.25-second UTC step relative to monotonic; provider has not raised the shared >1-second incident | Registrar clock_skew and permanent fence; no JWT despite shared health | PT6 |
| T18 | No in-place clock recovery | After T5/T14/T15/T16/T17, restore good evidence, acknowledge and wait, but do not restart | Original process never reopens, resets its barrier or releases a JWT | PT4 |
| T19 | Wall progress cannot complete hold | Advance UTC by 4 seconds while only 0.5 monotonic seconds elapse; attempt to fix start | Still no qualified start or admission; only monotonic elapsed time counts | PT1 |
| T20 | Only shared production provider supplies evidence | No provider sample, but a production path substitutes a local healthy flag or unqualified synchronization status | Startup fenced; test fixtures do not authorize a production bypass | PT1 |
| T21 | Serving after a lifetime fence | Fence a serving process, offer fresh otherwise valid proofs before/during drain, and restore provider health before it exits | No new admission or JWT; existing late accounting follows the retention rules above. Continuing to serve fails; successful drain leads to code 75, never in-place reopening | PT8 |
| T22 | Replacement launched before old exit (deployment negative) | Supervisor launches the replacement while the fenced old process is still draining, even if old admission has stopped and new checks appear healthy | Deployment qualification fails the exit-before-launch premise; replacement admission MUST NOT be enabled | PT8 |
| T23 | Drain failure cannot masquerade as a clock exit | After a clock fence, independently inject a failed/timed-out handler join or detached-audit drain; attempt code 75 or sink closure with pending work | Existing shutdown failure remains non-zero (currently 1), with `registrar: shutdown failed`; no code 75 or premature sink closure, no JWT | PT8 |
| T24 | Rate-limit stop requires operator recovery | Failed starts exhaust the configured start limit and stop the unit; restore provider health and wait past the limit interval without operator action | No automatic restart or admission after the limit stop; healthy evidence and elapsed time do not replace operator recovery | PT9 |
| PT1 | Healthy fixed start and new barrier | Both provider checks healthy/unexpired within cap; hold exactly 4 monotonic seconds; fixed UTC=1004.3, barrier=1035; at now=1035 offer fresh iat=1035 and nonce | Admit otherwise valid proof once; one reservation/debit per budget, one JWT | PR1 |
| PT2 | Inclusive provider boundaries | At fixed-instant check all sources nts, selected name or address matches; leap Normal, sync age=2048, offset=+0.5 or -0.5, root distance=1, delta_sample=1.5; authority fresh; initial check also passed, full hold completed | Provider gates and startup pass at inclusive bounds; fresh proof at the barrier admits | PT1 |
| PT3 | Small new sample retains common hold | T4 old process/launch readings; new delta_sample=0.1 but hold=4, fixed UTC=1004.61, barrier=1035; at now=1035 replay old iat=1032 then use fresh iat=1035 and nonce | Old proof clock_skew without reservation/debit; fresh control admits once | PT1 |
| PT4 | New process recovers, old process stays fenced | After a clock fence, exclude old process; new process independently passes both provider checks, holds 4 seconds and fixes a new barrier | Fresh proof at the new barrier admits only in the new process; old remains fenced | PT1 |
| PT5 | Authority not yet expired: separate startup/admission controls | (a) Sample UTC=1000; first check UTC=1295.999 (age=295.999); hold 4; fixed recheck UTC=1299.999 (age=299.999), barrier=1330. Refresh authority before UTC=1300; later at UTC=1330 use fresh iat=1330 and nonce. (b) Already-qualified process fixed at UTC=1000, barrier=1031, sample UTC=1000; at UTC=1299.999 (age=299.999) offer fresh iat=1299 and nonce, finish release before UTC=1300, then refresh before age=300 | (a) Near-expiry startup check passes with no immediate JWT; later proof admits under refreshed authority. (b) Barrier/skew and unexpired authority hold throughout issuance; one JWT. Each issuance reserves/debits once; all other provider gates healthy | PT1 |
| PT6 | Normal monotonic progression | Qualified process, healthy fresh provider evidence; UTC advances continuously with monotonic, including repeated floored integer readings | No false backward-step fence; fresh proof at/after barrier admits | PT1 |
| PT7 | Client backoff includes hold | Healthy fixed start after H=4; client is 30 seconds behind; by fixed instant+61 seconds (initial check+65, ignoring added latency) request new proof and nonce | Fresh proof satisfies barrier/skew; old proof is not rehabilitated; extras require stated margin, not indefinite proof replay | PT1 |
| PT8 | Supervised clock recovery | Fence -> stop admission -> join pending handlers and detached audit -> close sink -> exit 75 with `registrar: clock fenced` -> supervisor restart after old exit within the start budget. New initial UTC=1000; both checks pass, hold=4 monotonic seconds, fixed UTC=1004, barrier=1035; at UTC=1035 use fresh iat=1035 and nonce, all other gates valid | No operator needed for this clock restart; no old/new overlap, no JWT before the new barrier; the new proof admits once, with one reservation/debit per budget | PT1 |
| PT9 | Operator recovery after start-limit stop | T24 unit remains stopped; operator diagnoses and repairs the cause, clears the start-limit failure and explicitly starts it; repeat the healthy PT8 path with fresh evidence | Restart resumes only after operator action and old exit; both checks/full hold still required, fresh proof at the new barrier admits once | PT8 |

A future lifecycle harness must kill bounded controls that (a) skip/shorten the
hold at T2/T3, (b) use only the new sample at T4, (c) ignore the second check at
T14 and (d) ignore subsecond backward steps at T17, while PT controls remain
green. These are planned requirements, not passing production-test evidence.

## Appendix C. Decisions, open questions and source-gap choices (informative)

### C.1 Decisions (informative)

These decisions are settled and normative in the defining sections.

| Decision | Contract | Reason |
| --- | --- | --- |
| P2 | `uid_map` is required on every station host. Group-only mode is removed entirely; there is no legacy flag. | Per-station OS accounts must define the helper authorization boundary. |
| P3 | Phase 0 trusts a pinned, verified signed-commit registry revision; any `sigs` member is refused. The target is per-record owner-device signing. | Publish a verifiable phase-0 authority while keeping future owner-signature semantics explicit. |
| P5 | Registrar and Keymaker read the same pinned revision from configured local paths, with the same verification rule; location is deployment-owned. | Do not bake registry placement or mutable fetching into the admission protocol. |
| E1 | Phase 0 requires one offline Ed25519 enrollment-publisher signature; the owner holds the key offline. Root-owned, non-agent-writable configuration pins the publisher key out of band, the maintainer allowlist and approved revision; both services verify commit and envelope with the same pins and rule (§4.3). | Accepted by the content review; preserve signed envelopes alongside signed-commit authority. |
| HS2 / HS4 | A reviewed change to the operated homeserver must provide access-token expiry without refresh-token issuance and refuse JWT login for deactivated accounts. Deployment is blocked until that change is qualified; specification, vectors and service code continue. | The pinned stock login path does not meet these requirements; the homeserver change is the chosen path. |
| HS3 | Accept the stock 60-second JWT leeway, including equality; revocation accounts for `exp + 60`. | The accepted bearer exposure matches the inspected validator. |
| Access-token lifetime | Accept 86,400 seconds without refresh-token issuance. | Use the accepted 24-hour target; deployment still requires the qualified homeserver change. |
| KM1 | Bind the Keymaker reference to landed main head `f5bbba2281c224c2c120cc422644cc8a1fda1bf8`, cited in §1. | Keep the helper contract in Keymaker; the landed reference has been verified. |
| JWT | `nbf=iat` and `exp=iat+120` for every issued JWT. | Keep the issued lifetime fixed independently of proof lifetime. |
| Components | Registrar owns formats/data semantics; Keymaker owns the helper interface, peer enforcement and host key. | Each normative contract has one component owner. |

### C.2 Decision status and activation dependencies (informative)

The content review settled the choices below. Remaining dependencies are the
reviewed homeserver change and its qualification. They do not block
specification, vector or service-code work
and do not permit an unsupported service activation. E1 is settled in C.1 and
§4.3; it is not an open question.
Option C has additional proposed activation prerequisites in C.3.

| Item | Decision | Status |
| --- | --- | --- |
| HS1 | Explicit `algorithm="EdDSA"` is required in addition to `format="EDDSA"`; the source independently selects the algorithm and defaults to HS256. | Source-confirmed configuration correction. |
| HS2 | The reviewed homeserver change must provide 86,400-second access-token expiry without refresh-token issuance. | Decided; deployment blocked pending that change and its qualification. |
| HS3 | Accept stock 60-second JWT leeway, including equality; revocation accounts for `exp + 60`. | Accepted; no remaining leeway choice. |
| HS4 | The reviewed homeserver change must refuse JWT login for deactivated accounts. Keep §11's lock/containment and logout procedure. | Decided; deployment blocked pending that change and its qualification. |
| KM1 | Use the Keymaker specification at landed main head `f5bbba2281c224c2c120cc422644cc8a1fda1bf8` in §1. | Bound; cited helper, peer-UID and enrollment contracts verified at the landed head. |
| Access-token lifetime | 86,400 seconds without refresh-token issuance. | Accepted; deployment still gated by HS2 qualification. |

Other source-gap choices made for determinism are listed completely by category:

| Choice | Reason |
| --- | --- |
| 64 KiB registration/enrollment envelope, depth 16; 10,000 records / 16 MiB registry | Bound parsing, signature work and registry loading; envelope size follows the broker framing precedent without importing its socket ownership. |
| Canonical unpadded base64url with zero trailing bits; raw 64-byte signatures | Remove multiple spellings and cross-library signature encodings. |
| Strict Ed25519 subgroup/canonical-point checks, including R and S | Avoid weak-key and verifier-dependent acceptance; refusal maps stay explicit. |
| Wire string caps: key 128 ASCII bytes, name 255 UTF-8 bytes, audience 255 ASCII bytes | Bound parsing before later semantic checks; allow recognized bad key-length fixtures to reach the signature verdict. |
| Years 1970–9999, no leap seconds; positive proof duration | Whole-second parsing and Unix JWT conversion must have one result. |
| Prefix selects key algorithm; recognized bad points/lengths use signature-invalid | Make the CIP's key-confusion test deterministic without algorithm guessing. |
| Offline publisher key class and one out-of-band public pin | Preserve a true signed enrollment envelope without an undefined phone/owner-root format or registrar custody of another secret. |
| Enrollment history files, whole-snapshot validation and duplicate-position rejection | Highest valid sequence must not mean silently ignoring a malicious invalid newer record. |
| Irreversible host tombstones, non-reassignment of historical keys and durable high-water/restore fence | A valid old signed revision is not proof of current revocation authority. |
| Half-open key windows; check both iat and current time; overlapping distinct keys allowed | Make exact window edges and rotation behavior unambiguous. |
| Enrollment limits: 16 keys, 256 explicit names, 256 UID entries, 64 names per UID | Bound configuration complexity while accommodating ordinary station hosts. |
| UID integer range 1–4294967294; one row per UID; disjoint names across UIDs | Exclude root/sentinel ambiguity and avoid multiple station identities sharing an authorization boundary. |
| Literal optional absolute POSIX executable path with no ambiguous components | Publish portable syntax while leaving kernel/executable proof to Keymaker. |
| Structured project/role/qualifier lengths and character sets; qualifier is variable | CIP gives a shape, not these token limits; disallow underscores inside tokens for unique host parsing. |
| Conservative lowercase legacy localpart grammar and configured-audience 255-byte mxid bound | Preserve exact legacy exceptions without admitting Matrix case folding or arbitrary reserved punctuation. |
| No cross-host explicit structured-name claims; legacy explicit names cannot move across hosts even through history | Preserve namespace attribution and prevent stale historical claims from authorizing reassignment; same-host removal/re-addition remains allowed. |
| Exact media-type parameters, identity-only content encoding and 404/405 routing | Avoid implicit decoder and routing-dependent refusal behavior. |
| SP/HTAB around media-field values and charset separators; contiguous `=` and unquoted charset values | Follow RFC 9110 whitespace boundaries while deliberately narrowing its quoted parameter syntax to an unquoted charset token. |
| Ordered HTTP checks, empty error details, final authority and signing-generation revalidation | Multi-defect vectors need one result; cancel pending old-key issuance at cutover rather than release an already invalid token. |
| Snapshot-wide loader phases in bytewise Git-path order; conflict before rollback | Combined-defect snapshots need a single diagnostic independent of filesystem traversal. |
| Separate authority, accounting, audit and readiness fixture oracles | Rejection forbids unauthorized authority changes while permitting mandatory nonce consumption, limiter debits, audit appends and fences. |
| Thirty-second proof skew and barrier floor(fixed start)+31; common 1.5-second error cap, 4-second monotonic pre-start hold, two provider checks and permanent process fence | Preserve restart ordering across bounded clock error and clock recovery. Proposed local choices are in C.4; aligned-client cost is 4+31=35 seconds and the 30-seconds-behind horizon is 4+61=65 seconds, plus stated latency margins. A failed-start or ever-fenced process never reopens. |
| No durable replay cache or clock/admission-time high-water mark in version 0 | Rely on the explicit synchronized-start ordering premise and fail closed when it cannot be established. A durable clock/admission-time high-water or replay store is a later design option requiring separate qualification; the existing durable registry high-water remains required. |
| Nonce scoped to key, consumed at reservation even after later failure, held until exp+30 | Bound memory and eliminate racing/retry double issuance. |
| Sliding 60-second budgets: key 10, name 3; lower only to integer capacities at least 1; authenticated-stage charging only | Bound signing load without unauthenticated quota exhaustion or undefined retry delays from zero capacity. |
| JWT iat is issuance time; no kid; PKCS#8 private / SPKI public PEM | Separate proof freshness from fixed token lifetime and match one-key homeserver verification. |
| Local durable audit plus off-host acknowledgement before release; 5-second deadline | Off-host audit cannot be claimed from best-effort buffering, and sink stalls must be bounded. |
| Typed runtime/audit/registry errors and loader-only diagnostics | CIP lists admission refusals but leaves infrastructure and enrollment validation failures unnamed. |

### C.3 External-witness rulings and activation dependencies (informative)

Content review on 2026-10-23 accepted the option C specification, including
write-ahead intent before Store.Commit and fencing old authority when an intent
append fails. This accepts the specification, not implementation or activation.
WC1–WC5 below have accepted directions and remain open for activation;
implementation and activation wait until all five are closed. The source
contracts (§4.4, §9 and the current local adapters) do not supply a production
witness, fresh-head protocol or instance-exclusion mechanism.

Until option C is activated, option A with its four shared invariants applies
unchanged (§4.4 and the documented `serve --reconcile` procedure):

1. The starting process obtains interactive exact-digest confirmation against
   trustworthy surviving evidence outside the restored failure domain.
2. Confirmation lasts only for that process; every restart needs confirmation,
   with no persisted receipt or reusable local freshness flag.
3. No flag, environment variable or non-terminal input supplies the digest.
4. Missing high-water never implies first use; bootstrap needs explicit
   protected configuration for the exact pin and the same confirmation.

| Specification choice | Reason / ruling |
| --- | --- |
| Digest the complete version-1 canonical high-water, including ownership/history, with SHA-256 and no LF | Reuse current local-state bytes; a revision or current-sequence-only hash would omit irreversible evidence. |
| Separate typed witness stream over the §9 channel; LF-inclusive record hash and exact receipt | Reuse authenticated off-host durability without changing the closed admission-audit schema or mixing sequence spaces. |
| Stable protected stream binding; positive safe-integer sequence, hash continuity and compare-head append | Prevent empty-stream resets, accidental consumer collisions and conflicting records at one position. |
| Stream id limited to 128 ASCII identifier bytes; sequences bounded by CCJ-1 safe integers; exhaustion fences | Bound record parsing, avoid identifier normalization and forbid counter wrap. |
| Acknowledged witness intent, local commit, acknowledged matching resolution, then authority use | Accepted on 2026-10-23: a whole-host restore can erase any local pending marker before a post-commit witness append. The write-ahead external intent preserves that obligation for both changed-state and unchanged-state commits. |
| Intent failure leaves old authority fenced with no Store.Commit; operator alone resolves an actual unresolved intent | Accepted on 2026-10-23: preserve §4.4 failed-reload safety and avoid treating an uncertain external append or restored local bytes as freshness evidence. |
| Fresh challenge-bound authoritative latest read, not cached receipt equality | A valid old receipt and rolled-back local file can agree while both are stale. |
| Five-second default per witness operation; fence on failure, explicit option A recovery | Bound startup/reload waiting while preserving the existing failure-closed rule. |
| Reuse registry_unavailable for witness fences, preserving restricted loader diagnostics | Registry authority is unavailable; this introduces no HTTP or helper refusal code. |
| Preserve single-instance serving; separate consumer-bound streams on one service | Witness compare-head serialization does not fence an already signing process; no helper-internal design is imported. |
| B.2 lifecycle plans have separate W/PW ids | Do not imply new byte-vector fixtures or executable conformance in this specification-only slice. |

The following directions are accepted; their implementation details and
qualification remain open for activation. None may be silently supplied by a
local file or an audit shipping adapter.

| Item | Status | Accepted direction / activation evidence needed |
| --- | --- | --- |
| WC1 | direction accepted, open for activation | An independently administered append-only service outside the platform's failure domain with a separately retained trusted checkpoint; qualify independent restore, continuity and joint-loss bounds. Exact placement is an owner infrastructure decision and does not block this ruling. |
| WC2 | direction accepted, open for activation | A typed witness stream over the §9 audit channel with challenge-bound linearizable latest-head reads; close framing, peer authentication, provisioning, rotation, limits and continuity-proof details before implementation. |
| WC3 | direction accepted, open for activation | Separate consumer-bound streams on one external service with common registry/pin policy; qualify each consumer without defining Keymaker internals here. |
| WC4 | direction accepted, open for activation | Exclude the old serving instance before replacement and throughout authority use; qualify exclusion. Any distributed lease requires separate review of signing fences. |
| WC5 | direction accepted, open for activation | An operator runbook bound to the exact digest, intent hash, revision and independent surviving history evidence; close authorization/evidence records, bootstrap, repair/migration, mode changes and loss-of-evidence handling. Exact-candidate completion is specified; cancellation/replacement still needs a separate explicit decision and cannot be inferred from restored local bytes. |

No service code, socket implementation, vector files, live-account tests,
network-registry API or deployment change is included in this specification slice.

### C.4 Platform-time alignment and proposed local choices (informative)

The 2026-10-23 platform trusted-time ruling uses one shared policy/provider,
owned by the credential-broker project. The intended document is **Platform time
policy**, `docs/time-policy.md`; it is not yet published. Its exact reviewed link
and provider integration/qualification remain activation dependencies, recorded
in UNRESOLVED_QUESTIONS.md. Section 7 specifies the target; this slice adds no
provider implementation or deployed clock qualification. Policy option A/B here
concerns time-source evidence, separately from §4.5 reconciliation option A/C.

| Proposed local choice | Reason / content-review status |
| --- | --- |
| Common protected delta_cap=1.5 seconds, enforced at every admission and both startup checks; provider reports delta_sample as offset magnitude plus root distance | Proposed for content review: both lifetimes must obey the same conservative bound. A new-only sample cannot establish the prior admission's error; T4/PT3 retain that counterexample. A cap above the policy bound is refused. |
| Fixed monotonic hold 2*delta_cap+1=4 seconds; one whole second of additional margin | Proposed for content review: absorb both error bounds and make strict ordering explicit without carrying prior-process time state. Never shorten it from a small new sample. |
| Fix start only after the hold and successful second provider check | Proposed for content review: preserve the floor(fixed start)+31 barrier while checking freshness/health at its derivation. The old process must stop admitting before launch. |
| Reject variable hold delta_cap+delta_sample+1 | Rejected alternative: 2.6 seconds at sample=0.1, up to 4 at sample=1.5, versus fixed 4; it adds sample/hold/recheck coupling with no extra safety. New-sample-only 2*delta_sample+1 is unsafe, not an optimization. |
| Any detected backward UTC step fences the registrar for its process lifetime | Proposed for content review: stricter than the shared >1-second incident/hold; health loss and authority expiry have the same permanent fence. |
| Clock-fence exit code 75 and fixed `registrar: clock fenced` diagnostic after successful shutdown drain | Proposed dedicated type: distinct from configuration/non-clock startup/drain failures (currently generic exit 1). Drain failure retains its own failure and never becomes a successful clock-fence exit. Implementation belongs to the evidence-source slice. |
| Supervisor example: Restart=on-failure, RestartSec=2s, StartLimitIntervalSec=60s, StartLimitBurst=5 | Recorded operating choice for deployment review: start only after old exit, bound restart loops, and require the operator after a limit stop. Values may be tuned with a finite rate budget; they never shorten the hold or waive other admission gates. |
| Client horizon 4+61=65 seconds plus evidence/scheduling/transport margin | Proposed for content review: replace the former 61-second startup budget; Keymaker clients obtain a new proof/nonce and diagnose persistent refusal rather than replay indefinitely. |
| Preserve 310 legacy byte fixtures as abstract post-hold admission inputs | Explicitly approved fixture boundary: R125 is not a realizable new-start trace. B.3 alone plans real provider/hold lifecycle qualification. No vector bytes or row text change. |

Option A still infers selected-source NTS status from configuration. Authenticated
per-source evidence needs option B's separately qualified root-granted data.
Neither the local choices nor the provider's healthy verdict prove a compromised
source's UTC bound or qualify two concurrently serving instances.
