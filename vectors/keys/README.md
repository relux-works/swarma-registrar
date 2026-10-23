# Public test material only

Every value in `seeds.json` is a published test value. These keys MUST NEVER
be used for deployment, accounts, enrollment authority or operational signing.
They are public and provide no security. The tools never read operational keys.

The three Ed25519 seeds are test vectors 1–3 in
[RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032.txt).
The P-256 scalar is the example in
[RFC 6979 Appendix A.2.5](https://www.rfc-editor.org/rfc/rfc6979.txt).
Additional Ed25519 test keys are derived as SHA-256 of the host seed bytes
followed by the ASCII fixture label; each label is recorded by the generator.
Test nonces are fixed byte sequences, deliberately unsuitable for live requests.

P-256 test signatures use a deterministic, test-only nonce derived from SHA-256
of the published scalar, message digest and a counter. This is not an RFC 6979
implementation and must not be reused for production signing. The independent
checker verifies the resulting ordinary ECDSA signatures with `cryptography`.
