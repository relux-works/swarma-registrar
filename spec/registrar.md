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

The helper interface belongs to **Keymaker specification**, operations
`hello { versions: [1] }` and `sign_registration { name, aud }`. Keymaker uses
the framing convention in broker §13.1. This document MUST NOT be treated as a
second socket or helper-refusal specification. Its `uid_map` format is the data
contract Keymaker consumes. An implementation MUST bind the exact Keymaker
specification revision before activation; its publication is an open dependency.

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
`r || s`, each an unsigned 32-byte big-endian scalar; DER is not accepted.
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

### 4.3 Phase-0 signatures and pins (decisions P3, P5) (normative)

The registry MUST be read from a configured local, non-agent-writable path at
an explicitly configured full Git commit object id. Registrar and Keymaker
MUST use the same configured revision, audience and verification rule. Location and
transport of that registry are deployment matters. Neither service follows a
mutable branch, fetches implicitly, or treats a working tree as authority.

The pinned commit MUST have a valid signature under an out-of-band configured
registry-maintainer verification-key allowlist, and MUST be the reviewed
protected-branch revision approved by the operator. A valid signature alone
does not prove review; the deployment pin is the operator's approval evidence.
Commit-author text, an embedded key and mere object existence are not trust.

To preserve the signed-envelope construction, **this draft additionally requires
an offline Ed25519 enrollment-publisher signature** in `sig`. The publisher is
a record-signing key class, separate from host keys, JWT keys, broker roots and
future phone/device keys. The verifier knows exactly one current publisher
public key in the §3.1 `ed25519:` encoding from protected, out-of-band configuration; there is no body-supplied
issuer or key-selection hint. No private publisher key resides at the registrar
or helper. Rotation of this pin requires the operator to re-sign the loaded
record history and advance the approved registry pin atomically while retaining
body/sequence/tombstone history. It MUST NOT reset rollback state. Publisher
rotation changes envelope signatures but not record ids.

The signed commit is the phase-0 enrollment authority; the envelope signature
is an additional integrity check, not self-enrollment. This extra offline pin
is a proposal for a source gap (Appendix C); it does not implement `sigs[]` or
pretend a software key is a presence-gated owner signature.

### 4.4 Snapshot selection and rollback (normative)

A registry revision contains `enrollments/*.json`, each file one envelope,
with history retained append-only. Other paths are not enrollment inputs.
The aggregate MUST contain at most 10,000 envelopes and 16 MiB of envelope
bytes. Symlinks and nonregular enrollment entries MUST be rejected. Filename
spelling carries no authority. Every envelope MUST validate before any new
snapshot is installed. Invalid records MUST NOT be skipped to choose a lower
`seq`.

Enrollment validation order is: byte limit and CCJ-1/envelope shape
(`enrollment_malformed`); reserved `sigs` (`enrollment_sigs_unsupported`);
remaining body/key/name/UID schema (`enrollment_malformed`); recomputed id
(`enrollment_id_mismatch`); publisher signature (`enrollment_signature_invalid`);
then registry-wide/history checks (`registry_conflict` or
`registry_rollback` below). Failure refuses the entire load atomically.

Group records by exact host label. The highest valid `seq` is current; gaps
are allowed. Duplicate `(host, seq)` is `registry_conflict`, even for identical
bodies: there MUST be one record at each position. A host appearing at distinct
sequence positions is history, not a duplicate current host. A decoded public
key MUST NOT belong to different hosts anywhere in retained history, including
revoked hosts. An explicit legacy localpart MUST NOT be claimed by two hosts,
or fall under another host's structured namespace; such ambiguity is
`registry_conflict`. Prefix authorization of valid structured names otherwise
belongs uniquely to the parsed host.

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
The same rule applies at Keymaker. On any invalid/missing/unreadable registry,
unverifiable pin or failed reload, both services MUST stop new signing/issuance;
they MUST NOT continue using a possibly superseded snapshot. HTTP admission
returns `503 registry_unavailable`, with the loader diagnostic in restricted
operator logs. There is no network registry API in this version.

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
| 15 | Process clock is healthy and `iat >= start_barrier` (§7). | `clock_skew` | 400 |
| 16 | Request `iat <= now + 30`. | `request_not_yet_valid` | 403 |
| 17 | `now < request.exp + 30`. | `request_expired` | 403 |
| 18 | Both per-key and per-name budgets have capacity (§7). | `rate_limited` | 429 |
| 19 | `(key, nonce)` has not been consumed. Reserve it atomically. | `nonce_replayed` | 409 |
| 20 | Signer and service prerequisites work; all final authority/time checks still pass. | `service_unavailable` | 503 |
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
verdict discards the JWT and records a refusal with that original code. No
service state lock is held during off-host I/O. No failure releases a JWT.
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

The registrar MUST run as one replica. Scaling requires a shared, atomic nonce
store and a new qualified design. Store all times at integer-second precision
for comparison. Let `now = floor(current UTC Unix time)` for one check pass.
Set `start_barrier = floor(actual process-start UTC time) + 1`. Requests with
`iat < start_barrier` MUST be refused as `clock_skew`, without skew allowance.
The first partial second after startup therefore cannot admit a request. This
strict rounding avoids admitting a proof issued earlier in the restart second.
Keymaker should generate a fresh request after startup-related refusals.

The admission skew bound is 30 seconds. This allows ordinary synchronized-host
jitter while bounding the added replay period. Future `iat = now + 30` is
accepted; `now + 31` is refused. `now = exp + 29` may pass; `now = exp + 30`
is expired. These are request-proof rules, not homeserver JWT leeway. Hosts,
registrar and homeserver MUST have monitored clock synchronization. Loss of
synchronization or a backwards UTC step MUST fence admission (`clock_skew`)
until operator-validated recovery; retained nonce entries MUST NOT be cleared
to recover a clock. Monotonic clocks measure limiter intervals and watchdogs.

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
Operators MAY lower these two defaults; changes MUST be explicit configuration
and recorded in deployment/test evidence. Vector defaults are the values above.

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

Agent login requests MUST NOT request refresh tokens; credentials MUST NOT
persist one. The required access-token lifetime is 86,400 seconds, with no
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
meet §10.1. Deployment MUST remain blocked until an independently reviewed
homeserver change or a verified alternative version provides expiry without
refresh-token issuance. Discarding a refresh token client-side, requesting one
secretly, or asserting a CLI timeout is server-side expiry MUST NOT be used as
a substitute. The operator must resolve this conflict (Appendix C).

The 60-second JWT leeway is an explicit extension of nominal bearer validity,
not the registrar's 30-second proof skew. The operator MUST accept that exposure
or qualify a homeserver change with zero/configurable leeway before activation.
Revocation MUST account for a pending JWT being usable through `exp + 60`.
A claim that the stock homeserver rejects deactivated users' JWT logins is also
unsupported by this version. These are source-confirmed divergences from a
naive reading of the CIP, not unverified claims. No live compatibility claim is
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
pair, then resume. During mismatch, login MUST fail closed. Already issued old
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
| Clock manipulation | Monitored synchronization, conservative start barrier and fail-closed regression fence. A compromised time source can deny admission; this spec does not prove trustworthy time from a timestamp alone. |
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

A row with a temporal defect MUST keep both `iat` and current time inside the
key window unless the window itself is under test. Future/expiry controls MUST
adjust `start_barrier` so the restart check does not mask the intended result.
A name-length control MAY use a longer configured audience and an explicit
legacy name to reach precisely the mxid byte boundary. Body input order and
wire escaping can vary without changing signed canonical bytes.

For stateful rows the vector fixture MUST include prior registry/high-water,
clock, nonce, limiter or audit state and assert unchanged protected state on
rejection. Refusals MUST have no returned JWT. Loader failures MUST not install
partial authority. The positive control column names an actual planned row,
not agreement with a second implementation. Every planned vector is a separate
row; transport/state rows use the affected signing domain even when their
fixture is not itself a signed object.

## Appendix B. Negative-first vector plan (normative plan)

Canonicalization-only rows test the CCJ-1 codec independently of the body
schema; their success is `accept (codec)`. All other accepts mean admission,
registry installation or the specified emission assertion, not just parsing.

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
| R48 | registration/1 | P-256 raw format | DER signature instead of 64 raw bytes | registration_malformed | PR2 |
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
| R88 | registration/1 | Failed attempt counts | Replay debits name budget, next attempt exceeds it | rate_limited | PR14 |
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
| R113 | registration/1 | No JWT replay promise | Same issued JWT submitted twice in its accepted window | both logins may accept; same mxid | PR17 |
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
| I7 | A qualified replacement issues 24-hour access tokens without refresh tokens. | Stock v1.9.3 no-refresh login is an expected unsupported control, never a green expiry claim. |
| I8 | Coordinated registrar/homeserver key switch admits only current signatures. | Old signature refuses after switch; existing access tokens require separate logout. |
| I9 | CLI atomically persists exactly three credential fields with mode 0600. | JWT, password, refresh token and secret-bearing errors never reach file, stdout or logs. |
| I11 | Keymaker refuses a wrong audience before producing a proof. | Correct configured audience and permitted name produce a registrar-verifiable proof; refusal name belongs to Keymaker. |
| I12 | Keymaker obtains caller UID from the kernel and enforces uid_map. | Foreign UID, false executable evidence and unsupported peer credentials refuse under its own contract. |
| I10 | Restart refuses proofs from earlier in the same wall-clock second. | Fresh proof at/after the next-second barrier passes. |

A future test harness MUST demonstrate that its refusal/side-effect checker
fails on a bounded deliberate bypass (for example a nonce-check bypass producing
a second JWT). A crash or an unrelated setup failure is not that control.
These are planned gates, not passing implementation evidence.

## Appendix C. Decisions, open questions and source-gap choices (informative)

### C.1 Decisions (informative)

These decisions are settled and normative in the defining sections.

| Decision | Contract | Reason |
| --- | --- | --- |
| P2 | `uid_map` is required on every station host. Group-only mode is removed entirely; there is no legacy flag. | Per-station OS accounts must define the helper authorization boundary. |
| P3 | Phase 0 trusts a pinned, verified signed-commit registry revision; any `sigs` member is refused. The target is per-record owner-device signing. | Publish a verifiable phase-0 authority while keeping future owner-signature semantics explicit. |
| P5 | Registrar and Keymaker read the same pinned revision from configured local paths, with the same verification rule; location is deployment-owned. | Do not bake registry placement or mutable fetching into the admission protocol. |
| JWT | `nbf=iat` and `exp=iat+120` for every issued JWT. | Keep the issued lifetime fixed independently of proof lifetime. |
| Components | Registrar owns formats/data semantics; Keymaker owns the helper interface, peer enforcement and host key. | Each normative contract has one component owner. |

### C.2 Open questions (informative)

The source-gap proposals below bind this draft's vectors until content review
changes them. They do not reopen P2/P3/P5 and do not permit an unsupported
service activation. Changing a proposal requires updating its rules and plan.

| Question | Draft position and reason | Status |
| --- | --- | --- |
| E1 | Keep a real phase-0 enrollment envelope signature using a separately pinned offline Ed25519 enrollment publisher. CIP-0019 defines a signed envelope but no phase-0 signer/key-selection rule. | Proposed envelope detail for content review; additional publisher pin needs approval. |
| HS1 | Explicit `algorithm="EdDSA"` is required in addition to `format="EDDSA"`; the source independently selects the algorithm and defaults to HS256. | Source-confirmed correction to the CIP configuration example. |
| HS2 | Require 24-hour access expiry and no refresh-token issuance; stock v1.9.3 cannot supply both. Choose an upstream correction or a qualified alternative version. | Blocking operator/platform decision before deployment; no workaround proposed. |
| HS3 | Document stock 60-second JWT leeway, including equality, rather than asserting a strict 120-second accepted lifetime. | Operator must accept the longer bearer exposure or request a qualified change. |
| HS4 | Deactivation alone does not gate JWT login in the pinned source. Require lock/containment while outstanding JWTs remain usable and subsequent logout. | Procedure needs isolated qualification or a corrected homeserver version. |
| KM1 | Registrar owns data semantics; Keymaker owns socket, refusal and peer/executable enforcement. No second helper implementation/layout is introduced here. | Exact published Keymaker revision/link required before implementation activation. |

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
| No cross-host explicit structured-name claims | Explicit lists must not defeat the promised host namespace boundary. |
| Exact media-type parameters, identity-only content encoding and 404/405 routing | Avoid implicit decoder and routing-dependent refusal behavior. |
| Ordered HTTP checks, transport codes, empty error details and final revalidation | Multi-defect vectors need one result and no partial authorization release. |
| Thirty-second proof skew and strict next-second start barrier; clock failures fence issuance | Balance synchronized-host jitter against replay, including same-second restart exposure. |
| Nonce scoped to key, consumed at reservation even after later failure, held until exp+30 | Bound memory and eliminate racing/retry double issuance. |
| Sliding 60-second budgets: key 10, name 3; authenticated-stage charging only | Bound legitimate signing load without unauthenticated name-based quota exhaustion. |
| JWT iat is issuance time; no kid; PKCS#8 private / SPKI public PEM | Separate proof freshness from fixed token lifetime and match one-key homeserver verification. |
| Local durable audit plus off-host acknowledgement before release; 5-second deadline | Off-host audit cannot be claimed from best-effort buffering, and sink stalls must be bounded. |
| Typed runtime/audit/registry errors and loader-only diagnostics | CIP lists admission refusals but leaves infrastructure and enrollment validation failures unnamed. |
| Access-token target 86,400 seconds | CIP recommends 12–24 hours; use its recommended upper endpoint while retaining the explicit stock-version blocker. |

No service code, socket implementation, vector files, live-account tests,
network-registry API or deployment change is included in this draft.
