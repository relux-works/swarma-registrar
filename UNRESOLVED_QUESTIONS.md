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

KM1 is bound: the Keymaker reference in §1 uses landed main head
`f5bbba2281c224c2c120cc422644cc8a1fda1bf8`; the cited helper, peer-UID and enrollment
contracts have been checked.

Remaining dependencies:

- Service activation: production clock health/startup-ordering evidence and an authenticated durable off-host audit sink still need implementations and qualification. The binary supplies neither; it stays clock-fenced and never releases a JWT without remote acknowledgement. Interactive registry reconciliation alone cannot qualify them.
- HS2 / HS4: the chosen reviewed change to the operated homeserver must provide access-token expiry without refresh-token issuance and refuse JWT login for deactivated accounts. Deployment remains blocked until that change is qualified. Specification, vectors and service code continue meanwhile; §11's lock/containment and logout steps remain required.

These are implementation and qualification dependencies, not unresolved choices
of signer, leeway, token lifetime or homeserver-fix path. This file records no
passing deployment qualification.

## Media-type decisions

Content review on 2026-10-23 settled both questions. Section 6 permits SP/HTAB
around the complete field value and the charset-separating semicolon, forbids
whitespace inside tokens or around `=`, and requires an unquoted charset value.
Quoted charset values of any case yield `unsupported_media_type`; this is a
deliberate narrowing of RFC 9110's quoted parameter syntax. These choices are
no longer open. HTTP implementation alignment is a separate pending change.
