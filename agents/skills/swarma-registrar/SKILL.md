---
name: swarma-registrar
description: Use Swarma Registrar's Go libraries and HTTPS service for registration proofs, enrollment and pinned registry snapshots. Use for this module, not credential-broker helpers or general Matrix account management.
---

# Swarma Registrar

Use the implemented interface that matches the request:

- Read [Go library usage](references/go-library.md) for canonical bytes, proof construction and verification, enrollment policy, or registry queries. It includes an inert fixture and its neighboring refusal.
- Read [service usage](references/service.md) for the actual command, HTTP contract, configuration and reconciliation fences.
- Read [registry extensions](references/registry-extensions.md) when writing, wiring or testing a caller-supplied trust or storage adapter. Extension uses Go interfaces and loader fields; there is no plugin registration API.

The public import prefix is `github.com/relux-works/swarma-registrar/`; use its `ccj`, `envelope`, `registration`, `enrollment` and `registry` packages. The module declares Go 1.26.10. Internal service adapters and admission/HTTP packages are implementation components, not external import paths. Start with the [module README](../../../README.md) and the relevant public package source; use [the specification](../../../spec/registrar.md) for ordered checks and formats. Where older README status statements conflict with wiring, inspect the implementation linked by the references.

Keep proof data, enrollment authenticity, current registry authority and admission separate. Successful proof verification does not establish audience equality, enrollment permission, clock validity, replay/rate checks or audit acknowledgement. Registry lookup can return revoked or expired current records; check the key window, then revocation, then name authorization in the required order. Fence admission after any failed registry reload; retained snapshots are recovery evidence.

This module owns registrar admission and JWT issuance. The separate credential broker owns host-helper operations, registration-key custody and peer-UID enforcement. Do not infer a helper implementation, live qualification or permission to issue from a library result or offline fixture. Report the actual result and the checks still outside the selected interface.
