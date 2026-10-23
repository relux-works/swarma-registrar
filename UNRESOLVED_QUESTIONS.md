# Open questions

The settled decisions and the remaining proposals are in
[the decision appendix](spec/registrar.md#appendix-c-decisions-open-questions-and-source-gap-choices-informative).

P2, P3 and P5 are settled: station hosts require UID maps, group-only admission
has no legacy mode, phase 0 trusts the pinned verified signed-commit registry,
reserved `sigs` is refused, and registry placement is deployment-owned.

- E1: approve or replace the proposed offline Ed25519 publisher signature and pin for the phase-0 enrollment envelope. Signed-commit registry authority itself is settled.
- HS2: select a homeserver correction or qualified version that expires access tokens without issuing refresh tokens. Stock tuwunel v1.9.3 does not meet both requirements.
- HS3: accept the source-confirmed 60-second JWT leeway or qualify a stricter validator.
- HS4: qualify lock/logout ordering while outstanding JWTs remain usable; the pinned version does not gate JWT login on deactivation alone.
- KM1: bind the exact published Keymaker specification revision for helper framing, operations, peer UID/executable enforcement and refusal codes before activation.

The other source-gap choices are explicit in Appendix C for content review.
HS1 records a source-confirmed configuration correction (`algorithm="EdDSA"`).
This file records questions, not passing deployment qualification.
