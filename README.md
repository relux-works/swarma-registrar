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
| `UNRESOLVED_QUESTIONS.md` | Remaining activation dependencies and the open media-type whitespace question. |
| `vectors/` | 305 committed negative-first registration/enrollment fixtures and public test keys; all 305 Appendix B rows are instantiated. |
| `internal/` | Go byte formats, strict signatures, registration/enrollment validation and in-memory registry snapshots. |
| `cmd/registrar` (planned) | Registrar service binary in Go. |

## Status

Service (in progress): the Go core implements CCJ-1, signed envelopes, strict
key/signature checks, stateless registration/enrollment validation, in-memory
registry snapshots, an internal admission core and a net/http handler with
injected dependencies.
The repository also contains 305 offline format vectors, with a Go generator
and an independent Python checker. No service listener exists yet. These
fixtures do not qualify a running service or homeserver.
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

## Library packages

| Import path | Purpose |
| --- | --- |
| `github.com/relux-works/swarma-registrar/ccj` | Strict CCJ-1 parsing and canonicalization. |
| `github.com/relux-works/swarma-registrar/envelope` | Bounded envelope parsing and generic domain-separated signature verification. |
| `github.com/relux-works/swarma-registrar/enrollment` | One pinned publisher, enrollment schema and read-only verified records. |
| `github.com/relux-works/swarma-registrar/registry` | Phased snapshot validation, caller-supplied trust/storage interfaces and read-only queries. |

The implementations remain in `internal/`. Registration-proof verification stays
internal for the registrar. Package examples use fixed public test seeds. Generic
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

## Tools

| Tool | Purpose | Exact entry point | Output |
| --- | --- | --- | --- |
| Go 1.26 | Test the module, examples and public API inventories; run static validation. | `go test ./...`; `go test ./internal/...`; `go test -race ./internal/admission/...`; `go vet ./...` | Terminal diagnostics and Go build cache; no generated repository files. |
| Go conformance harness | Compare committed vectors against landed code and report pass/fail/pending counts per domain. | `go test -v ./internal/conformance`; narrow internal validation: `go test ./internal/...` | Terminal diagnostics; `CONFORMANCE_VECTORS` optionally selects a scratch vector copy. |
| Go (standard library) | Regenerate vectors or check exact committed bytes and file set. | `GOMAXPROCS=2 go run ./tools/vectorgen`; `GOMAXPROCS=2 go run ./tools/vectorgen -check` | `vectors/registration-1/`, `vectors/enrollment-1/`, `vectors/keys/seeds.json`, `vectors/keys/public-keys.json`; check mode writes nothing. |
| Python 3 with cryptography | Independently check CCJ-1, cryptography, ordered outcomes, JWT bytes and state. | `python3 tools/vectorcheck/check.py` (dependencies: `python3 -m pip install -r tools/vectorcheck/requirements.txt`) | Terminal verdicts; writes nothing. |
| Python unittest | Check signed HTTP media-token and structured-name regressions against the independent checker. | `python3 -B -m unittest discover -s tools/vectorcheck -p test_regressions.py -v` | Terminal verdicts; fixtures under `tools/vectorcheck/fixtures/` stay separate from the 305 planned vectors. |
| Git | Inspect scope and check documentation whitespace. | `git diff --check`; `git diff --stat`; `git diff -- spec/registrar.md README.md UNRESOLVED_QUESTIONS.md` | Terminal diagnostics and diff; no generated repository files. |
| curl | Retrieve the pinned public validator source for inspection. | `mkdir -p .temp/spec-source-review` then `curl --fail --location https://raw.githubusercontent.com/Keats/jsonwebtoken/900010fb1be550ec2cfa8c32038eb154f9ef56d7/src/validation.rs --output .temp/spec-source-review/validation.rs` | Source in the created task-scoped scratch directory. |
| Python 3 | Count the planned vector rows in the draft. | `python3 -c 'from pathlib import Path; s=Path("spec/registrar.md").read_text().split("## Appendix B.")[1].split("### B.1")[0]; print(sum(line.startswith("\u007c ") for line in s.splitlines())-2)'` | Terminal count only. |

Core tests derive their own inputs from fixed public test seeds and curve
parameters. Enrollment and registry validation use in-memory inputs. The registry
loader completes all seven snapshot-wide phases before a caller-supplied atomic
high-water store can publish the result. Commit verification binds the supplied
entry set to the exact approved signed revision; Git ancestry and durable storage
also come from caller-supplied interfaces. No live Git, file reader, network or
process state is implemented. The deployment supplies a validated canonical
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
no-store headers. Surrounding media-header whitespace remains unspecified;
implementation comments describe the current MIME parser behavior. Tests use
`httptest` without a listener. HTTPS, transport deadlines, ingress limits and
concrete clock, signer, storage and off-host adapters belong to deployment.
Registration parsing verifies schema, id and signature in that
order. Name syntax and audience checks are separate methods
so admission can run enrollment checks first, as required by specification §6.1.
Future service tooling must document its entry points here.

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
Registration has 86 executed rows and 80 named pending stages; these counts do
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
