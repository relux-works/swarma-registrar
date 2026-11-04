# swarma-registrar v0.1.0

## Release identity

- Version: **v0.1.0**.
- Binary source commit: **b0bee3c45f112a4109a92f52bdcc885860e81dfd**.
- The release tag will point to the documentation-only commit that pins
  `GOEXPERIMENT` and `GOFIPS140` in this recipe. The binary is unchanged because
  the build uses `-buildvcs=false` and the source is unchanged.
- The tag is signed with the platform release key at installation time.
  No tag is created by this documentation change, and no binary is published.

## Reproducible build

Use the **official Go 1.26.10 toolchain**. Confirm that `go version` reports
`go1.26.10`; automatic toolchain selection must not substitute another version.
Start from a fresh clean checkout of the release commit, with an empty Go build
cache (`GOCACHE`) and a separate module cache (`GOMODCACHE`). Run from the module
root:

```sh
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS=-mod=readonly GOEXPERIMENT= GOFIPS140=off
go build -trimpath -buildvcs=false -ldflags=-buildid= -o registrar ./cmd/registrar
sha256sum registrar        # or: shasum -a 256 registrar
```

`GOEXPERIMENT` and `GOFIPS140` are pinned because inherited values change the binary; the installer must use the export line verbatim.

Expected output artifact: Linux, amd64, GOAMD64 v1, without cgo.

| Property | Expected value |
| --- | --- |
| SHA-256 | `8b3c3f18d71a8350de406e6dae2bf58d9073c0af371c5143d61cadac4cde2e7b` |
| Size | 11,668,143 bytes |

The reference was reproduced twice from separate clean checkouts and caches.
An additional independent build on 2026-11-04, using macOS arm64 and
`go version go1.26.10 darwin/arm64`, cross-compiled with the recipe above and
matched both the SHA-256 and size.

## Installer verification

The installer must verify the release tag's signature against the platform
release key, check out that signed tag, and build with the exact recipe and
toolchain above. Compare the resulting SHA-256 and size with the expected values.
**Stop installation on any mismatch. Only the verified binary is installed.**
A matching build does not qualify a deployment or homeserver.

## Security checks

`govulncheck` **v1.1.4**, running under **Go 1.26.10** on release commit
`b0bee3c45f112a4109a92f52bdcc885860e81dfd`, reports `No vulnerabilities found.`
The additional independent run on 2026-11-04 scanned `./...` with the recipe's
Linux/amd64 environment and exited 0:

```text
=== Symbol Results ===

No vulnerabilities found.

Your code is affected by 0 vulnerabilities.
This scan also found 0 vulnerabilities in packages you import and 1
vulnerability in modules you require, but your code doesn't appear to call these
vulnerabilities.
Use '-show verbose' for more details.
```

The verbose scan identifies the module-only finding as **GO-2026-5024** in
`golang.org/x/sys/windows` (`golang.org/x/sys` v0.38.0; fixed in v0.44.0), affecting
Windows. It reports no affected symbols or imported packages for this Linux
target. This result is scoped to this source, target and vulnerability database
at scan time.

## Included

- Registration and enrollment admission.
- JWT issuance gated on the off-host Matrix audit-room acknowledgement, with
  reconciliation.
- Production time evidence through the shared time-confidence provider.
- The audit-identity refusal.

## Not qualified yet

- **Live homeserver qualification** under specification §10.3 and Appendix B.1,
  HR1–HR14 and I16–I21, including server-side transaction deduplication retention.
- **Deployment on a real host.**
- **Audit-journal compaction for very long chains.**

These remain open qualification limits; the source release and reproducible
build do not establish them.
