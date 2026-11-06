# Service usage

## Actual command and flags

From the module root, `go build ./cmd/registrar` builds `registrar`. The implemented serving command is `./registrar serve --config /etc/registrar/config.json`; the path is an illustrative operator-provisioned location, not a bundled configuration. Building does not configure or qualify a deployment.

| Flag | Implemented meaning |
| --- | --- |
| `--config` | Required path to the protected startup JSON. Unknown arguments and positional leftovers refuse. |
| `--reconcile` | Validate the pinned candidate and request terminal confirmation of rollback evidence for this process before durable publication. |
| `--loopback-test-http` | Permit plain HTTP only on a literal loopback IP/port. DNS, wildcard, non-loopback and scoped addresses refuse. It does not supply clock evidence or bypass registry/audit checks. |

Source: [main.go](../../../../cmd/registrar/main.go), `run`, `openProduction`, `wire`; [transport.go](../../../../cmd/registrar/transport.go), `transport`. The module/toolchain declaration is in [go.mod](../../../../go.mod). The executable's test injection hooks are not selectable flags or configuration fields.

## Configuration and startup

Use the [startup configuration reference](../../../../internal/adapters/README.md#startup-configuration) and the actual strict parser, [config.go](../../../../internal/adapters/config.go), `LoadConfig`/`ParseConfig`. The JSON has version `v: 1`, a canonical configured audience, an exact approved registry revision and protected publisher/signer/source/storage pins. `object_format` must be `sha1` or `sha256`; it is never inferred from the revision. Unknown, duplicate, missing or mistyped fields refuse. Configured paths are absolute and clean, without expansion.

The protected configuration is root-owned; run under an unprivileged service UID. Private signer, TLS, state and audit files have their own ownership/mode requirements. Refer to the existing adapter documentation rather than copying paths, keys or credentials into examples.

Ordinary serving requires TLS material and a protected `time_policy`. The production constructor starts the shared clock provider even in loopback mode; the test flag cannot assert a healthy clock. The binary wires production clock evidence and an optional Matrix audit delivery session. The audit profile's `audit_homeserver`, `audit_room`, `audit_user` and `audit_token` fields must appear together, with the required `audit_retired_localparts` list. The token is loaded at startup. Without authenticated remote acknowledgement an otherwise issuable request refuses `audit_unavailable`.

Inspect [timeconf_linux.go](../../../../internal/adapters/timeconf_linux.go), `NewProductionClock`; [audit configuration](../../../../internal/adapters/audit_config.go), `parseAuditConfig`; [audit wiring](../../../../internal/adapters/audit_delivery.go), `OpenAudit`/`ConnectMatrix`; and the [Matrix adapter contract](../../../../internal/adapters/matrixaudit/README.md). Some older README paragraphs say no remote sink/listener exists; `openProduction` and `OpenAudit` implement those connections. That wiring does not close the documented live qualification gaps.

## Reconcile without bypassing freshness

Add `--reconcile` to the serving command only for deliberate reconciliation. `startRegistry` otherwise installs no registry authority. Reconciliation authenticates the complete candidate before prompting; confirmation gates the actual store commit, not a provisional snapshot.

Compare the displayed local high-water digest, pinned revision and candidate enrollment IDs with trustworthy surviving evidence outside the restored failure domain. Supply the exact displayed digest through the controlling terminal. Nonterminal input, EOF, padding and partial/wrong values refuse. There is no noninteractive confirmation switch or persisted freshness receipt. Every process needs a new confirmation. Missing state permits bootstrap only when protected `first_use` exactly names the configured revision; missing evidence alone never implies first use.

On a failed commit, authority is absent and durable state may be indeterminate. Preserve evidence and reconcile again before admission. Source: [reconcile.go](../../../../cmd/registrar/reconcile.go), `startRegistry`, `reconcile`, `confirmingStore.Commit`, `confirmEvidence`, `bootstrapDigest`; [terminal_linux.go](../../../../cmd/registrar/terminal_linux.go), `openTerminal` (other platforms refuse through [terminal_other.go](../../../../cmd/registrar/terminal_other.go)).

## HTTP outcomes and limits

`GET /readyz` returns JSON readiness; a closed registry/clock/signer/audit fence yields 503. `POST /v1/registration` accepts the signed registration envelope. The handler limits actual received bytes to 65,536 before media/parsing checks, then checks schema, ID and signature before admission. It accepts `application/json`, optionally unquoted `charset=utf-8`, with the exact whitespace/encoding grammar in `supportedMedia`; do not rely on MIME normalization to widen it.

Success returns 200 with a `jwt` field. Refusal JSON contains `code`, a fixed message and empty `details`, with `Cache-Control: no-store`. Method refusal advertises POST; rate limiting can return `Retry-After`. Return the actual status/code to callers; losing a response does not refund its nonce or authorize reissuing its JWT.

Source: [HTTP handler](../../../../internal/httpapi/handler.go), `Handler.ServeHTTP`, `supportedMedia`, `status`, `writeRefusal`; [readiness wiring](../../../../cmd/registrar/main.go), `wire`; [admission](../../../../internal/admission/admission.go), `Admitter.Ready`, `Admitter.Admit`.

A process-lifetime clock fault fences admission; successful drain/close exits 75, while failed shutdown retains failure status. Offline fixtures, loopback controls and TLS fakes do not qualify production clock trust, blocked kernel I/O, remote audit durability/retention or homeserver behavior. Keep the open deployment gates in the [README](../../../../README.md#status) and [Matrix adapter documentation](../../../../internal/adapters/matrixaudit/README.md) explicit; a proof, reconciled registry or readiness observation alone does not establish complete deployment qualification.
