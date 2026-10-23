# swarma-registrar

Carrier admission: an enrolled host proves possession of its key, and the
registrar issues a short-lived Matrix login JWT for a permitted name.

Lore: **Morpheus** — the registrar that admits identities to the carrier.

## Scope

- **Registrar** (this repository): owns `registration/1`, `enrollment/1`, their envelopes, `uid_map` data semantics, registry verification, HTTPS admission, JWT issuance and audit. It holds only its own JWT private signing key.
- **Keymaker** (separate module): owns the host helper, socket, peer-UID enforcement, helper refusals and custody of the host registration key. Its operations are `hello` and `sign_registration`; this repository does not implement a host helper.
- Human SSO and credential-broker grants have separate owners.

The design reference is [CIP-0019](https://github.com/relux-works/curator-spec/blob/main/cips/CIP-0019-carrier-admission-by-public-key.md).
The [module specification](spec/registrar.md) defines exact draft rules,
ordered refusals and a negative-first vector plan. Settled decisions and remaining
activation dependencies are in [open questions](UNRESOLVED_QUESTIONS.md).

## End state

A future bridge appservice owns the carrier namespace. Per-agent JWT login is
transitional; the reusable core is key proof → enrollment → carrier credential.

## Layout

| Path | Purpose |
| --- | --- |
| `spec/registrar.md` | Draft normative formats, HTTP API, registry rules, source findings and vector plan. |
| `UNRESOLVED_QUESTIONS.md` | Remaining activation dependencies, proposed external-witness choices and settled media-type decisions. |
| `vectors/` | 310 committed negative-first registration/enrollment fixtures and public test keys; all 310 Appendix B byte-vector rows are instantiated. The separate §B.2 witness and §B.3 time-provider/startup lifecycle plans have no fixtures. |
| `internal/` | Go byte formats, strict signatures, registration/enrollment validation and in-memory registry snapshots. |
| `internal/adapters/` | Offline pinned Git, durable local state/audit, file signer, clock evidence boundary and strict startup configuration. |
| `cmd/registrar/` | HTTPS registrar binary with interactive, process-scoped rollback reconciliation. |

## Status

Service (in progress): the Go core implements CCJ-1, signed envelopes, strict
key/signature checks, stateless registration/enrollment validation, in-memory
registry snapshots, an internal admission core and a net/http handler with
injected dependencies.
The repository also contains 310 offline format vectors, with a Go generator
and an independent Python checker. The first service binary wires the local
adapters, HTTPS, admission and HTTP. It remains fenced without production clock
evidence and cannot issue without an authenticated remote audit sink. Offline
fixtures and loopback tests do not qualify a deployment or homeserver.
Source inspection of tuwunel v1.9.3 found that `access_token_ttl` alone cannot provide
access-token expiry without refresh-token issuance, and JWT login does not
refuse deactivated accounts. A reviewed change to the operated homeserver must
provide both requirements; deployment stays blocked until that change is
qualified. Specification, vectors and service code continue meanwhile.

The offline enrollment-publisher signature and protected common pins, stock
60-second JWT leeway, and 86,400-second access-token target are accepted.
The Keymaker specification is bound to landed main head
`f5bbba2281c224c2c120cc422644cc8a1fda1bf8`; its cited helper, peer-UID and enrollment
contracts have been checked (KM1). See specification §1, §4.3, §10 and Appendix C.

The [time-policy target](spec/registrar.md#7-time-replay-concurrency-and-limits-normative)
requires the shared platform provider, a 4-second monotonic hold and two startup
checks before fixing the replay barrier. Its provider/startup lifecycle plans
remain uninstantiated; the existing binary does not yet implement this target
and remains fenced without production clock evidence.

## Library packages

| Import path | Purpose |
| --- | --- |
| `github.com/relux-works/swarma-registrar/ccj` | Strict CCJ-1 parsing and canonicalization. |
| `github.com/relux-works/swarma-registrar/envelope` | Bounded envelope parsing and generic domain-separated signature verification. |
| `github.com/relux-works/swarma-registrar/registration` | Build canonical registration proofs, check unsigned names/schema, assemble caller signatures and verify rows 5–7. |
| `github.com/relux-works/swarma-registrar/enrollment` | One pinned publisher, enrollment schema and read-only verified records. |
| `github.com/relux-works/swarma-registrar/registry` | Phased snapshot validation, caller-supplied trust/storage interfaces and read-only queries. |

The implementations remain in `internal/`. The registration facade accepts public
keys and raw signatures; callers sign outside the package and self-check with
`registration.Verify` before release. `Build` and `Check` use a trusted configured
audience for the name byte cap; audience equality and admission authority remain
caller responsibilities. See the package example (`go test ./registration`) for
the build/sign/assemble/verify flow. Package examples use fixed public test seeds. Generic
envelope verification does not validate enrollment schema or publisher authority;
use the enrollment policy or registry loader for those checks. Key lookup returns
current-record data, including revoked hosts and expired windows; callers check
window validity and revocation in the required order.

Any public API or loader behavior change requires its own reviewed pull request.
Consumers pin a reviewed commit that has landed on main and raise that pin in
their own reviewed change. Each package's `api.txt` lists exported identifiers,
including fields and inherited methods;
`go test ./...` rejects additions/removals until that reviewed list is updated.
This name inventory does not detect signature or behavioral changes or prove
that a change received review. An unchanged `api.txt` or green inventory test is
not approval for a signature or behavior change. No test updates the inventories
automatically.

## Run the registrar

Build from the module root with Go 1.26, Git and OpenSSH installed:

```sh
go build ./cmd/registrar
./registrar serve --config /etc/registrar/config.json
```

The default listener requires HTTPS certificate and key files. It loads the
protected configuration, signed pinned registry source, high-water store, PKCS8
JWT signer and durable local audit chain. `GET /readyz` returns 503 until a
verified registry snapshot is installed and the admission clock/signer/audit
fences allow readiness. `POST /v1/registration` retains the specified ordered
refusals. SIGINT/SIGTERM shuts down the listener and drains requests for up to
five seconds. It then joins accepted HTTP handlers and admission work, including
bounded local refusal appends that outlive their HTTP responses, before closing
the audit sink. Handler and admission joins each have a ten-second observation
bound; those joins do not extend the existing request/cleanup budgets. A failed
HTTP grace period, join timeout or failed detached refusal is a failed shutdown
(non-zero exit with a static diagnostic). On a failed join the sink is left open
until failed process exit, rather than closed under pending work. HTTP header/body/write/idle deadlines are 5/10/10/30 seconds, with
a 16 KiB header limit. These limits do not qualify blocked local kernel I/O.

Plain HTTP requires the explicit `--loopback-test-http` flag **and** a literal
loopback listener, for example `127.0.0.1:8443` or `[::1]:8443`. Wildcard,
non-loopback, DNS and scoped addresses are refused in that mode. This flag does
not bypass ownership, registry, clock or audit checks. There is no CLI or
configuration switch that asserts a healthy clock or supplies a remote audit sink.

### Configuration reference

Use one root-owned regular JSON file, not writable by the service or group/other;
run the service as an unprivileged dedicated UID. Unknown, duplicate or missing
required fields, coercions and invalid paths are rejected. The complete base
schema, pin syntax and custody requirements are in the
[adapter configuration reference](internal/adapters/README.md#startup-configuration).
Required fields are `v` (integer 1), `audience`, `repository`, `revision`,
`allowed_signers`, `publisher_key`, `stations`, `high_water`, `signing_key` and
`audit_file`. Optional `per_key`/`per_name` default to 10/3 and can only reduce
those capacities. All configured file paths are absolute and clean, without
expansion; example paths here are operator-owned installation locations.

The binary adds these optional fields to that same strict schema:

| Field | Rule |
| --- | --- |
| `listen` | Literal IP address and port; default `127.0.0.1:8443`. No DNS resolution. |
| `tls_certificate`, `tls_key` | Both or neither; absolute clean paths. Required by `serve` unless the loopback test flag is present. Both files must be service-owned regular 0600 files in service-owned 0700 immediate directories. Final symlinks are refused. The certificate/key pair is loaded once, with TLS 1.2 minimum. |
| `first_use` | If present, the exact full `revision` string; authorizes proposing bootstrap for that pin when high-water is absent. A boolean, different pin or empty string is refused. Still requires terminal confirmation; remove this setting after deliberate first bootstrap. Never use it to replace lost rollback evidence. |

Keep signing, TLS, state and audit files separate. Root-owned configuration and
allowed-signers material, protected parent namespaces and a trusted executable
search path remain operator requirements. Configured paths, underlying parser
errors, private material and raw request text are excluded from diagnostics.
Configuration/pin/signing/audit custody failures prevent startup. Registry
reconciliation failures instead leave a running process registry-fenced.

### Reconcile when starting

The single reconciliation command is:

```sh
./registrar serve --config /etc/registrar/config.json --reconcile
```

Run it from a controlling terminal with terminal stdin. It authenticates the
pinned candidate and validates the full registry against retained history before
prompting. It prints the SHA-256 of the canonical locally stored high-water,
the exact pinned revision and every candidate enrollment ID, in sorted order.
Compare them with trustworthy surviving records **outside the restored failure
domain**. The tool cannot discover whether an old but valid local backup is fresh;
the operator supplies that attestation. Do not confirm merely because the digest
matches the local file.

Illustrative session (the digest/IDs must come from the actual validated state):

```text
$ ./registrar serve --config /etc/registrar/config.json --reconcile
Local high-water digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
Pinned registry revision: 2222222222222222222222222222222222222222
Enrollment IDs to accept:
sha256:3333333333333333333333333333333333333333333333333333333333333333
Verify this evidence against trustworthy surviving records outside the restored failure domain.
Type exactly sha256:1111111111111111111111111111111111111111111111111111111111111111 to authorize this process only: sha256:1111111111111111111111111111111111111111111111111111111111111111
```

Only the exact complete digest line is accepted: no whitespace padding, partial
input, wrong value, EOF or nonterminal stdin. There is no confirmation flag,
environment variable or piped-input path. The command reads its controlling
terminal, then commits the validated state through the Store's full-state CAS
and durability contract. A state change while the prompt is open refuses rather
than overwrite another writer's evidence. No snapshot becomes usable before
that commit succeeds.

Confirmation applies to this process only. No receipt, reconciled flag or local
freshness marker is persisted. Every restart needs a fresh confirmation; an
ordinary `serve` starts registry-fenced and prints the reconciliation command.
A rejected confirmation leaves it fenced without changing the high-water.
Missing high-water is refused unless the protected `first_use` field explicitly
names this pin. For that deliberately configured first use, the prompt states
that evidence is absent and asks for a domain-separated digest of the approved
pin; the operator must confirm that displayed digest before the initial Store
commit. Missing or corrupt evidence is never silently treated as first use.

| Condition | Behavior |
| --- | --- |
| No confirmation, wrong/missing/nonterminal confirmation or unverified registry | No installed registry; readiness 503, admission `registry_unavailable`. |
| Missing state without explicit configured first-use pin | No bootstrap or state write; registry remains fenced. |
| Store commit failure or concurrent replacement | No authority returned; durability may be indeterminate. Reconcile again against surviving evidence in a new process. |
| No production clock evidence source | Permanent process clock fence; readiness 503, valid enrolled requests refuse `clock_skew` (400). Waiting never reopens it. |
| No authenticated remote audit sink | Local refusals can be durably spooled; an otherwise issuable request refuses `audit_unavailable` (503), with no JWT release. |

The shipped binary has neither production clock evidence nor a remote sink.
Successful reconciliation establishes registry authority only; it does not
establish clock ordering, off-host durability or deployment readiness. The
loopback issuance control injects trusted fixed-time evidence and an exact-hash
in-memory remote; these test adapters are not selectable in the executable.

## Tools

| Tool | Purpose | Exact entry point | Output |
| --- | --- | --- | --- |
| Go 1.26 | Test the module, examples and public API inventories; run static validation. | `go test ./...`; `go test ./internal/...`; `go test -race ./internal/admission/...`; `go vet ./...` | Terminal diagnostics and Go build cache; no generated repository files. |
| Registrar command | Build and run the HTTPS service; confirm rollback evidence interactively. | `go build ./cmd/registrar`; `./registrar serve --config /etc/registrar/config.json --reconcile`; command checks: `go test ./cmd/registrar` | The build writes `registrar` in the current directory; service writes protected high-water/audit files configured below. Terminal diagnostics contain no key paths. |
| Go conformance harness | Compare committed vectors against landed code and report pass/fail/pending counts per domain. | `go test -v ./internal/conformance`; narrow internal validation: `go test ./internal/...` | Terminal diagnostics; `CONFORMANCE_VECTORS` optionally selects a scratch vector copy. |
| Go 1.26, Git and OpenSSH ssh-keygen | Check local adapters and internal packages; create disposable signed Git fixtures with generated test keys. | `GOMAXPROCS=2 go test ./internal/...`; `GOMAXPROCS=2 go vet ./...`; focused adapter checks: `go test ./internal/adapters` | Terminal verdicts; fixture files in Go's temporary directory (set `TMPDIR` to a scratch directory). No network. |
| Go (standard library) | Regenerate vectors or check exact committed bytes and file set. | `GOMAXPROCS=2 go run ./tools/vectorgen`; `GOMAXPROCS=2 go run ./tools/vectorgen -check` | `vectors/registration-1/`, `vectors/enrollment-1/`, `vectors/keys/seeds.json`, `vectors/keys/public-keys.json`; check mode writes nothing. |
| Python 3 with cryptography | Independently check CCJ-1, cryptography, ordered outcomes, JWT bytes and state. | `python3 tools/vectorcheck/check.py` (dependencies: `python3 -m pip install -r tools/vectorcheck/requirements.txt`) | Terminal verdicts; writes nothing. |
| Python unittest | Check signed HTTP media-token, structured-name and reachable-accounting regressions against the independent checker. | `python3 -B -m unittest discover -s tools/vectorcheck -p test_regressions.py -v` | Terminal verdicts; fixtures under `tools/vectorcheck/fixtures/` stay separate from the 310 planned vectors. |
| Git | Inspect scope and check documentation whitespace. | `git diff --check`; `git diff --stat`; `git diff -- spec/registrar.md README.md UNRESOLVED_QUESTIONS.md` | Terminal diagnostics and diff; no generated repository files. |
| curl | Retrieve the pinned public validator source for inspection. | `mkdir -p .temp/spec-source-review` then `curl --fail --location https://raw.githubusercontent.com/Keats/jsonwebtoken/900010fb1be550ec2cfa8c32038eb154f9ef56d7/src/validation.rs --output .temp/spec-source-review/validation.rs` | Source in the created task-scoped scratch directory. |
| Python 3 | Count the planned vector rows in the draft. | `python3 -c 'from pathlib import Path; s=Path("spec/registrar.md").read_text().split("## Appendix B.")[1].split("### B.1")[0]; print(sum(line.startswith("\u007c ") for line in s.splitlines())-2)'` | Terminal count only. |

Core tests derive their own inputs from fixed public test seeds and curve
parameters. Enrollment and registry validation use in-memory inputs. The registry
loader completes all seven snapshot-wide phases before a caller-supplied atomic
high-water store can publish the result. Commit verification binds the supplied
entry set to the exact approved signed revision; Git ancestry and durable storage
also come from caller-supplied interfaces. The [local adapters](internal/adapters/README.md)
implement offline pinned Git, durable file state/audit, a protected PKCS8 signer,
strict startup configuration and system time with explicit health evidence.
The deployment supplies a validated canonical
audience, protected pins and externally reconciled rollback evidence. After any
reload failure, the caller must fence admission rather than reuse an older
snapshot. The internal admission core runs checks 8–21 with injected clock
and monotonic deadlines, Ed25519 signer and durable audit interfaces. It owns
process-local limits, consumed nonces, permanent clock fences and signing-key
generations. Callers publish registry changes and key cutovers through its release
serialization. Local audit sequencing honors each request's cancellation.
After an expired request, a separate bounded local refusal-spool attempt does
not delay its response or reopen the audit fence; exact-head recovery is explicit.
The caller supplies actual startup-ordering evidence, random
process ID and retained audit-chain head. The internal/httpapi package provides
`httpapi.New(admitter)` and a standard `net/http` Handler for checks 1–7 at
`POST /v1/registration`. Mount it directly to preserve routing refusal behavior.
It bounds received bodies, audits early refusals and writes safe JSON with
no-store headers. Section 6 now fixes media-header OWS boundaries and requires
unquoted charset values. The HTTP layer enforces those boundaries before MIME
normalization, retaining the raw unsupported-parameter guard. Tests use
`httptest` without a listener. The binary adds HTTPS and bounded transport
reads/writes; its integration tests listen only on loopback. Deployment still
owns ingress policy, production clock evidence and authenticated off-host audit.
Registration parsing verifies schema, id and signature in that
order. Name syntax and audience checks are separate methods
so admission can run enrollment checks first, as required by specification §6.1.
The binary supplies admission/HTTP wiring and interactive operator
reconciliation as described below. Production clock evidence and authenticated
off-host audit remain unconfigured; local adapters cannot establish those
deployment facts.

`go test -v ./internal/conformance/...` runs the offline fixture harnesses;
`go test -v ./internal/conformance/... -run '^TestAdmissionVectorConformance$'`
selects the registration HTTP/admission path. It prints separate pass, fail and
pending counts, checks exact responses, JWTs, audit lines and accounting, and
replays declared restart, clock, revocation and signing-generation traces through
injected interfaces. R105 reaches its initial accounting through three preceding
requests (issued, replay, replay), retains their audit chain, then executes the
unchanged main request. R83, R84, R86, R87, R111, R129, PR13, PR14 and PR18
start with empty accounting and declare successful signed requests in `before`.
Each timed request carries `now` (UTC seconds) and `monotonic_now` (elapsed whole
seconds); omitted per-request monotonic time retains the fixture default. The
main request uses the fixture's original times. Prefix nonces, both budget
histories and every audit line are retained. R111 also checks `Retry-After: 1`
and successful release at second 61; PR13 prunes only the event at second 0.
The independent checker executes these same declared requests, derives their
verdicts/JWTs and compares exact accounting; it does not install the target state.
Initial registry permission comes from fixture rollback evidence, separately from
empty storage; missing evidence fences admission. The older prefix harness
retains its own classifications. The media rows R138, R139, PR31, PR32 and PR33
execute through the aligned HTTP layer. The HTTP/admission harness reports
171 passed, zero failed and zero pending registration rows.
Read-only inspection checks private accounting after requests have quiesced;
it never seeds or modifies service state. External adapters and live concurrency
remain unqualified. `go test -race ./internal/conformance/...` checks this harness
under the race detector; commands print diagnostics without generating files.

Run both vector checks from the repository root. The generator uses only Go's
standard library; the checker uses the pinned Python dependency. See the
[fixture contract](vectors/README.md) for inputs, state oracles and limits, and
[public test material](vectors/keys/README.md) for seed provenance. Control plants
belong in an isolated scratch copy, passed with generator `-out <copy> -check`
and checker `--vectors <copy>`; they must never alter committed fixtures.
There is no registrar service listener or live integration target yet.

The [checker regressions](tools/vectorcheck/README.md) exercise signed neighboring
inputs and exact refusal, JWT and state expectations without expanding Appendix B.

The Go conformance harness executes all 139 enrollment-domain rows, including
101 complete public-loader scenarios and the retained envelope, signature and
codec checks. All 96 formerly deferred enrollment rows reach landed checks.
Registration has 86 executed rows and 85 named pending stages; these counts do
not qualify HTTP, admission, clock or audit behavior.

Loader scenarios explicitly classify bootstrap versus reload. Legacy bootstrap
fixtures receive operator approval from the row classification; the harness
never infers first use from missing storage. Prior authority is established by
a separate approved public-loader call, including the old publisher pin during
rotation. Fixture commit trust, exact entries, ancestry and persistence results
flow through the public caller interfaces. Refused candidates return no new
snapshot and preserve prior evidence. Validation refusals never call the store;
the persistence-failure fixture necessarily attempts one failed CAS. Successful
loads must match the full historical ID oracle, permanent ownership, revision
and exact highest-sequence current bodies. The adapter does not implement loader
validation or qualify real Git verification, storage durability or admission
fencing.
