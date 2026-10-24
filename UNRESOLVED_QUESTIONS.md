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

- Service activation: the shared Platform time policy provider, the §7 two-check/4-second startup ordering and an authenticated durable off-host audit sink still need integration and qualification. The binary supplies neither production evidence source; it stays clock-fenced and never releases a JWT without remote acknowledgement. Interactive registry reconciliation alone cannot qualify them.
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

## External high-water witness rulings and activation dependencies

Content review on 2026-10-23 accepted the option C specification (§4.5 and
Appendix B.2). Both reviewed choices are accepted: externally acknowledged
write-ahead intent before Store.Commit, and fencing old authority when intent
append fails, even if no local commit occurs. A lost receipt cannot establish
that the append failed. This is specification acceptance, not implemented or
qualified witness support.

Until option C is activated, option A with its four shared invariants applies
unchanged (§4.4 and the documented `serve --reconcile` procedure):

1. Interactive exact-digest confirmation in the starting process against
   trustworthy surviving evidence outside the restored failure domain.
2. Process-lifetime confirmation only; every restart needs confirmation, with
   no persisted receipt or reusable local freshness flag.
3. No digest supplied by flag, environment variable or non-terminal input.
4. Missing high-water never implies first use; bootstrap needs explicit
   protected configuration for the exact pin and the same confirmation.

Appendix C.3 records the accepted directions and remaining activation work:

- **WC1 — direction accepted, open for activation:** placement decided on 2026-10-24: a separate trust-node VPS at a provider independent of the platform, administered only by the owner, with no agent or platform administrative access. The append-only witness and co-located owner registry use separate accounts, processes and streams; the registry writer cannot append to witness streams. The trusted checkpoint is retained off that VPS. Residual risk: loss of that VPS loses both services, fences the registrar and requires option A recovery. Option A remains in force until option C is deployed and qualified. Placement is settled; deployment and qualification of restore, continuity and joint-loss bounds remain open.
- **WC2 — direction accepted, open for activation:** a typed witness stream over the §9 audit channel with challenge-bound linearizable latest-head reads; close transport, authentication, provisioning, rotation, limits and continuity-proof details.
- **WC3 — direction accepted, open for activation:** separate consumer-bound streams on one external service with common registry/pin policy; qualify both consumers without defining Keymaker internals.
- **WC4 — direction accepted, open for activation:** exclude the old serving instance before replacement and throughout authority use; qualify exclusion. Any distributed lease requires separate review of signing fences.
- **WC5 — direction accepted, open for activation:** an operator runbook bound to the exact digest, intent hash, revision and independent surviving history evidence; close authorization/evidence records, bootstrap, repair/migration, mode changes and loss-of-evidence handling. Cancellation/replacement remains a separate explicit decision; local restored bytes never authorize it.

Implementation and activation wait until WC1–WC5 are closed and qualification
evidence is supplied. This does not reopen specification acceptance. No automatic
downgrade, empty-stream bootstrap or joint-rollback detection is claimed.

## Platform time policy publication and qualification

The credential-broker project owns [Platform time policy](https://github.com/relux-works/swarma-credential-broker/blob/191c0c35aa2f4e6a850246b26c05c0462ff96c41/docs/time-policy.md)
and one provider behind an evidence-source interface for all three services.
The document is published at the pinned revision; the publication/link item is
closed. Production provider integration and qualification of both startup
checks, the fixed 4-second monotonic hold and lifetime fences remain required;
this specification slice implements none. The three policy differences are
resolved: alignment of §7's strict sync-age boundary, exclusive authority endpoint
and conservative uncertainty calculation was accepted on 2026-10-24. This
specification alignment does not qualify the provider or its integration.

Content review on 2026-10-23 accepted the §7 and Appendix C.4 common protected
1.5-second error cap, one-second hold margin, fixed-start interpretation and
stricter registrar backward-step fence. Keymaker clients must align their retry
budget to 4+61=65 seconds plus evidence/scheduling/transport margin and acquire
fresh proofs/nonces. B.3 plans startup qualification separately from the
unchanged legacy byte fixtures. Option A infers NTS from configuration;
authenticated per-source evidence remains option B work, not a claimed result.
These time-policy option labels are separate from witness reconciliation modes.
