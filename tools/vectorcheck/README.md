# Independent vector checker and regressions

Run from the repository root with the same pinned dependency as `check.py`:

```sh
python3 -B tools/vectorcheck/check.py
python3 -B -m unittest discover -s tools/vectorcheck -p 'test_*.py' -v
```

The checker reads the single `abstract-post-hold-rows-v1` JSON-array marker in
Appendix A. It discovers reserved-marker candidates across the whole spec before
checking location or syntax: exactly one candidate is allowed, it must be in
Appendix A, and its complete line and JSON must use the canonical syntax.
Discovery counts indented, inline and malformed candidates, including those
outside Appendix A. It then requires exact set equality with rows carrying
`actual_start_millis`, `start_barrier`, `startup_verified`, `clock_healthy` or
`clock_fenced`. It checks field presence, including false/default values, in
`fixture`, `before` and `after`; scheduled `clock` events carrying `healthy` also
count. All 310 current vectors carry these inputs, including enrollment and
codec rows that inherit shared defaults. Duplicate declarations and rows,
undeclared field-bearing rows and declared field-free rows fail.

Appendix B.3 must contain negative hold rows T1–T4 before its PT controls.
Every negative startup row must name a PT control, and every control chain must
resolve without cycles to a positive legacy vector row. These checks preserve
the declaration and the startup **plan**; they do not execute the provider checks
or qualify the four-second production hold. No vector bytes are changed.
The Go generator and conformance harness continue to consume the legacy byte
rows; they do not need to interpret this documentation inventory declaration.

`test_time_declaration.py` supplies paired rejection/valid-control regressions
for both inventory mismatch directions, malformed declarations, missing hold
rows, field-presence derivation, row ordering and control resolution. These tests
read the real specification and vectors and mutate copies in memory. Named CLI
regressions also check outside/malformed/indented competitors, same-line markers,
single-candidate location/syntax and existing missing/duplicate controls, each
paired with the clean CLI. CLI tests use temporary directories; `TMPDIR` selects
their scratch root. Run logs and any CLI control plants belong in an external scratch directory, outside the
tracked vector inventory; the checker writes no output artifacts.

The twenty static JSON fixtures under `fixtures/` exercise `check.verify`, including
envelope ids, signatures, ordered verdicts, exact JWT bytes and resulting state.
They retain the PR1 or PE1 base row metadata so the checker applies ordinary
signature rules. They are neighbors of those rows, outside the Appendix B file
inventory; neither the generator nor the 310-vector checker inventory includes
them. The test requires every fixture to be exercised.

Four named tests read the corresponding Appendix B media and name rows directly,
including PR1 as a media control. They check the precise planned defect/boundary
witness as well as the independently computed outcome, JWT and final state.

Expected verdicts come from specification sections 4.1, 5 and 6. The fixtures
were authored from PR1 and PE1, with changed envelopes signed using only the
fixed published RFC 8032 seeds in `vectors/keys/seeds.json`. Expected ids and JWT
bytes were constructed independently of the checker. No operational key is used.

| Named test | Required behavior and forbidden neighboring outcome |
| --- | --- |
| `test_media_type_token_boundaries` | `application/json`, `application/json;charset=utf-8` and `Application/JSON;Charset=UtF-8` accept; a space inside `application` refuses as `unsupported_media_type` without reservation. |
| `test_media_subtype_token_boundaries` | The same valid controls accept; a space inside `json` refuses as `unsupported_media_type` without reservation. |
| `test_signed_enrollment_structured_union` | A signed structured UID-map name with a leading-hyphen host accepts; putting that name in the legacy-only explicit list or exceeding the mxid byte cap refuses as `enrollment_malformed`, preserving prior authority. |
| `test_signed_registration_structured_union` | A signed structured request name with a leading-hyphen host accepts; exceeding the configured-audience mxid byte cap refuses as `name_invalid` without reservation. The registry UID map uses `legacy.dev` to isolate the request-name guard. |
| `test_planned_media_token_boundaries` | PR1/PR30 accept; R136/R137 refuse internal token spaces without reservation or debit. |
| `test_planned_media_ruling` | PR31–PR33 accept unquoted charset tokens and the permitted OWS boundaries; R138/R139 refuse quoted values and whitespace around `=` without reservation or debit. |
| `test_reachable_accounting_traces` | Nine nonce/budget rows execute legitimate signed prefixes from empty accounting and retain their outcomes. |
| `test_reachable_prefix_required` | Removing R83's prior issuance cannot be replaced by hidden nonce state. |
| `test_reachable_trace_clock_required` | PR13 needs explicit per-request clocks to reach the exact 60-second prune boundary. |
| `test_reachable_trace_clock_regression` | A backward monotonic trace is rejected; valid forward traces still pass. |
| `test_reachable_release_boundary` | R111 releases at second 61; the same attempt at monotonic second 60 remains limited. |
| `test_media_ows_boundaries` | SP/HTAB around `;`, the whole value or both accept; whitespace on either side of `=` refuses with unchanged authority/accounting and no JWT. |
| `test_media_unquoted_charset` | Unquoted charset tokens accept in either case; quoted lowercase and mixed-case values refuse with unchanged authority/accounting and no JWT. |
| `test_media_parameter_tokens` | The valid unquoted control accepts; spaces inside the charset parameter name or value refuse. |
| `test_media_ows_is_only_sp_htab` | The media predicate permits SP/HTAB at OWS boundaries and rejects CR, LF, vertical tab, form feed and non-ASCII whitespace; this focused predicate check makes no admission-state claim. |
| `test_planned_request_name_union_and_boundaries` | PR28/PR29 accept a leading-hyphen name, including the exact mxid cap; R134/R135 refuse the overlength and empty-role neighbors. |
| `test_planned_enrollment_name_union_and_boundaries` | PE14/PE15 install valid leading-hyphen enrollments; E112/E113/E114 refuse overlength, legacy-only explicit and empty-role neighbors. |

Specification §6 permits SP/HTAB around the complete field value and around
its charset-separating `;`. It forbids whitespace within type, subtype,
parameter-name and parameter-value tokens or around `=`. Charset values must
be unquoted in any case. Quoted values refuse as `unsupported_media_type`, a
deliberate narrowing of [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6),
which permits quoted parameter values. These are adopted rules, recorded in
[the media decisions](../../UNRESOLVED_QUESTIONS.md#media-type-decisions).
The checker already enforced these boundaries; the fixtures and exact row
witnesses now make that behavior an explicit regression contract.

The ordinary JSON fixture also supplies a positive control for the legacy UID-map
and explicit-list grammar. Long-audience neighbors use valid DNS labels; their
legacy explicit name fits the cap while their structured candidate exceeds it.
External trust, clock and sink results remain fixture inputs. These checks do
not qualify a service endpoint or deployment.
