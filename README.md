# swarma-registrar

Carrier admission for Swarma: a host (later an agent) proves possession of an enrolled key, and the registrar turns that proof into a short-lived carrier credential. The first carrier is Matrix (tuwunel `org.matrix.login.jwt`).

Design record: [CIP-0019](https://github.com/relux-works/curator-spec/blob/main/cips/CIP-0019-carrier-admission-by-public-key.md) (draft). Until the module spec is extracted, the CIP is the reference.

## Scope

- **Registrar** (this repo): verifies `registration/1` requests against `enrollment/1` records and issues a 120 s EdDSA JWT for the homeserver. It holds only its JWT signing key; it holds no host or agent keys.
- **Host helper** (this repo, separate component): the phase-0 keymaster. It signs only the `registration/1` domain for callers permitted by the enrollment `uid_map`, over a Unix socket framed like the broker (4-byte length + CCJ-1, `hello { versions: [1] }`). It runs as a dedicated service user, not root.
- **Not here:** human login (tuwunel GitHub SSO), the keymaster proper, grants (broker).

## End state

Under the Swarma bridge (book §6.2: agents do not read the carrier), agents stop holding carrier accounts and the bridge's appservice owns the namespace. Per-agent JWT logins are then a transitional a2a feature; the admission core (key proof → enrollment → carrier credential) is what stays. Size the module around that core.

## Layout (planned)

| Path | What |
| --- | --- |
| `spec/registrar.md` | normative formats, socket protocol, HTTP API, refusal codes |
| `vectors/` | canonical and negative vectors for `registration/1` and `enrollment/1` |
| `cmd/registrar`, `cmd/host-helper` | binaries (Go) |

## Status

Spec first: formats and negative vectors before any service code (CIP-0019 test plan).
