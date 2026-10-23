# Open questions

Settled decisions and remaining activation dependencies are in
[the decision appendix](spec/registrar.md#appendix-c-decisions-open-questions-and-source-gap-choices-informative).

P2, P3 and P5 are settled: station hosts require UID maps, group-only admission
has no legacy mode, phase 0 trusts the pinned verified signed-commit registry,
reserved `sigs` is refused, and registry placement is deployment-owned.
E1 is approved: the owner holds one offline Ed25519 enrollment-publisher key;
root-owned, non-agent-writable configuration supplies the out-of-band publisher
public pin, maintainer allowlist and approved revision. Registrar and Keymaker
verify commit and envelope with the same pins and rule. HS3 accepts stock
60-second JWT leeway, with revocation accounting for `exp + 60`. The
86,400-second access-token target without refresh-token issuance is accepted.
HS1 records the source-confirmed `algorithm="EdDSA"` configuration correction.

Remaining dependencies:

- HS2 / HS4: the chosen reviewed change to the operated homeserver must provide access-token expiry without refresh-token issuance and refuse JWT login for deactivated accounts. Deployment remains blocked until that change is qualified. Specification, vectors and service code continue meanwhile; §11's lock/containment and logout steps remain required.
- KM1: the Keymaker reference in §1 is cited at `35386512` and bound to the main head landed from PR #1. Re-check it against that landed main head before implementation activation.

These are implementation and qualification dependencies, not unresolved choices
of signer, leeway, token lifetime or homeserver-fix path. This file records no
passing deployment qualification.
