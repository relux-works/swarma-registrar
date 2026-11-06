# Go library usage

Import from `github.com/relux-works/swarma-registrar/`. The public facades delegate to internal implementations; do not import those internals from a consumer.

| Need | Public entry point | Boundary |
| --- | --- | --- |
| Strict canonical JSON | `ccj.Parse(data, malformed)` and `ccj.Marshal(value, malformed)` | Use a format-specific refusal code. Parsed numbers are `int64`, objects `map[string]any`, arrays `[]any`; duplicate members, lossy numbers and invalid UTF-8 refuse. Marshal accepts the supported parsed value types, not arbitrary structs or floats. |
| Generic signed envelopes | `envelope.SigningInput(domain, body)`, `envelope.Parse(raw, domain)`, `envelope.Verify(raw, domain, publicKey)` | Choose `envelope.Registration` or `envelope.Enrollment`. Parse checks bounded shape; Verify checks ID and strict signature against the supplied exact key. Neither establishes body schema, publisher provenance or admission authority. |
| Registration proof | `registration.Build`, `Check`, `Assemble`, `Verify` | Build/Check validate unsigned schema and names using the trusted configured audience. Assemble encodes a caller signature. Verify checks schema, ID and strict signature, in order, returning proof data. |
| Enrollment policy | `enrollment.NewPolicy(audience, publisher, stations)` then `Policy.Parse(raw)` | Supply one pinned Ed25519 publisher, a prevalidated canonical audience and independently trusted host classifications. Parse checks schema, ID and that publisher's signature; it does not select current registry authority. |
| Current registry authority | `registry.Loader.Load(input)` then `Snapshot.Current`, `LookupKey`, `Authorize` | Supply protected pins, complete entries, reconciled rollback evidence and trust/storage adapters. A snapshot is returned only after validation and durable CAS. See [registry extensions](registry-extensions.md). |

Sources: [CCJ facade](../../../../ccj/ccj.go) and [parser/canonicalizer](../../../../internal/ccj/ccj.go); [envelope facade](../../../../envelope/envelope.go) and [domain/shape implementation](../../../../internal/envelope/envelope.go); [registration facade](../../../../registration/registration.go); [enrollment facade](../../../../enrollment/enrollment.go) and [policy/record methods](../../../../internal/library/enrollment.go); [registry facade](../../../../registry/registry.go) and [loader/query methods](../../../../internal/library/registry.go).

## Build a registration proof

`registration.Body` contains `Key`, `Name`, `Audience`, `Nonce`, `IssuedAt` and `ExpiresAt`. Supply an exact prefixed public-key encoding, an independently generated 16-byte nonce and whole-second UTC timestamp strings (`YYYY-MM-DDTHH:MM:SSZ`). Schema validation requires expiry after issuance by at most 120 seconds; that does not check the current clock.

1. Call `registration.Build(body, configuredAudience)` to obtain canonical body bytes and the domain-separated signing preimage. On refusal both byte slices are nil. The audience argument comes from trusted configuration; Build does not compare it with `Body.Audience`.
2. Sign the returned preimage outside the package. Ed25519 signs the bytes directly. P-256 signs SHA-256 of those bytes, with a raw 32-byte `r` followed by 32-byte `s` and low S. Keep the body unchanged.
3. Call `registration.Assemble(canonicalBody, rawSignature)`. It requires exactly 64 signature bytes and canonicalizes the body; it does not verify or normalize the signature.
4. Call `registration.Verify(proof)` before releasing the proof. Its returned `Body` owns its nonce bytes. Name policy, audience equality, enrollment, clock, replay, rate limits and audit remain outside this call.

Read [ExampleBuild](../../../../registration/example_test.go) for the existing fixed-public-test-material build/sign/assemble/verify example. Its fixed nonce and signing seed are illustrative only. The public package generates no nonce or key, accepts no private key, and issues no JWT. [Implementation](../../../../internal/library/registration.go): `BuildRegistration`, `CheckRegistration`, `AssembleRegistration`, `VerifyRegistration`; [schema and ordered verification](../../../../internal/registration/registration.go): `parseBody`, `Read`; [signature rules](../../../../internal/sig/sig.go): `Verify`.

## Query enrollment and registry data

`Record.Keys`, `Names`, `UIDMap` and `CanonicalBody` return independent copies. `Window.ValidAt(issuedAt, now)` requires both instants inside the exact same half-open interval `[NotBefore, NotAfter)` without skew. `Record.Permits(name, policy.Audience())` checks name syntax/ownership only; never substitute a request-selected audience.

`Snapshot.LookupKey(key)` matches the exact encoding in current records only. Historical-only, unknown and malformed encodings do not match. A match may still be revoked or outside its window: check window validity, host revocation, then name authorization. `Snapshot.Authorize(host, name)` checks current host presence, revocation and names; it does not check a key, time or peer UID. Audience equality, clock policy, accounting and helper peer identity remain caller responsibilities.

See [enrollment contract](../../../../enrollment/doc.go), [registry contract](../../../../registry/doc.go), [record accessors](../../../../internal/library/enrollment.go) and [snapshot queries](../../../../internal/library/registry.go). Public package `api.txt` files inventory names, fields and methods; an unchanged inventory does not establish signature or behavioral compatibility.

## Inert fixture and adjacent refusal

This self-contained example adapts [ccj.ExampleParse](../../../../ccj/example_test.go). It uses fixed JSON only: no keys, files, network, registry authority or JWT issuance.

```go
package main

import (
    "errors"
    "fmt"

    "github.com/relux-works/swarma-registrar/ccj"
)

func main() {
    value, err := ccj.Parse([]byte(` {"z":2,"a":[true,1]} `), ccj.EnrollmentMalformed)
    if err != nil {
        panic(err)
    }
    canonical, err := ccj.Marshal(value, ccj.EnrollmentMalformed)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(canonical))

    _, err = ccj.Parse([]byte(`{"a":1,"a":2}`), ccj.EnrollmentMalformed)
    var refusal *ccj.Error
    if errors.As(err, &refusal) {
        fmt.Println(refusal.Code)
    }
}
```

Expected output from the existing public example:

```text
{"a":[true,1],"z":2}
enrollment_malformed
```

The second input has a duplicate member and must refuse. Inspect typed errors with `errors.As` and the package's `Error.Code`; do not echo raw inputs. Registry `Diagnostic.Path` is restricted operator context, while its `Error()` emits only the code.
