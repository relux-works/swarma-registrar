# swarma-registrar specification (draft)

Status: draft, derived from CIP-0019. Normative text, canonical bytes and vectors land here before implementation.

## Signing domains

- `swarma-registrar registration/1`: registration request envelope.
- `swarma-registrar enrollment/1`: host enrollment record.

Envelope construction follows swarma-credential-broker `spec/broker.md` §6.1: preimage = domain tag + `\n` + CCJ-1 canonical bytes of `body`; `id = "sha256:" + hex(SHA-256(preimage))`; `sig` over the preimage, outside the body.

## To be specified

1. `registration/1` body members and limits; Ed25519 and P-256 (raw r‖s, low-S) signatures.
2. `enrollment/1` members: host label grammar, keys with validity windows, names (prefix, explicit), `uid_map`, `seq`, `state` tombstones, optional owner `sigs[]`.
3. Host helper socket protocol and its single operation `sign_registration`.
4. `POST /v1/registration`, JWT claims (`iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`), refusal codes.
5. Canonical and negative vectors (CIP-0019 test plan).
