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
| `UNRESOLVED_QUESTIONS.md` | Remaining homeserver and Keymaker activation dependencies. |
| `vectors/` (planned) | Canonical and negative registration/enrollment vectors. |
| `cmd/registrar` (planned) | Registrar service binary in Go. |

## Status

Specification only. No service or vector implementation exists yet. Source
inspection of tuwunel v1.9.3 found that `access_token_ttl` alone cannot provide
access-token expiry without refresh-token issuance, and JWT login does not
refuse deactivated accounts. A reviewed change to the operated homeserver must
provide both requirements; deployment stays blocked until that change is
qualified. Specification, vectors and service code continue meanwhile.

The offline enrollment-publisher signature and protected common pins, stock
60-second JWT leeway, and 86,400-second access-token target are accepted.
The Keymaker specification is bound to landed main head
`f5bbba2281c224c2c120cc422644cc8a1fda1bf8`; its cited helper, peer-UID and enrollment
contracts have been checked (KM1). See specification §1, §4.3, §10 and Appendix C.

## Tools

| Tool | Purpose | Exact entry point | Output |
| --- | --- | --- | --- |
| Git | Inspect scope and check documentation whitespace. | `git diff --check`; `git diff --stat`; `git diff -- spec/registrar.md README.md UNRESOLVED_QUESTIONS.md` | Terminal diagnostics and diff; no generated repository files. |
| curl | Retrieve the pinned public validator source for inspection. | `mkdir -p .temp/spec-source-review` then `curl --fail --location https://raw.githubusercontent.com/Keats/jsonwebtoken/900010fb1be550ec2cfa8c32038eb154f9ef56d7/src/validation.rs --output .temp/spec-source-review/validation.rs` | Source in the created task-scoped scratch directory. |
| Python 3 | Count the planned vector rows in the draft. | `python3 -c 'from pathlib import Path; s=Path("spec/registrar.md").read_text().split("## Appendix B.")[1].split("### B.1")[0]; print(sum(line.startswith("\u007c ") for line in s.splitlines())-2)'` | Terminal count only. |

There is no build or executable test target in the current documentation scaffold.
Future services and vector tooling must document their entry points here.
