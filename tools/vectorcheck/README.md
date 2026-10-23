# Independent checker regressions

Run from the repository root with the same pinned dependency as `check.py`:

```sh
python3 -B -m unittest discover -s tools/vectorcheck -p test_regressions.py -v
```

The nine static JSON fixtures under `fixtures/` exercise `check.verify`, including
envelope ids, signatures, ordered verdicts, exact JWT bytes and resulting state.
They retain the PR1 or PE1 base row metadata so the checker applies ordinary
signature rules. They are neighbors of those rows, outside the Appendix B file
inventory; neither the generator nor the 293-vector checker inventory includes
them. The test requires every fixture to be exercised.

Expected verdicts come from specification sections 4.1, 5 and 6. The fixtures
were authored from PR1 and PE1, with changed envelopes signed using only the
fixed published RFC 8032 seeds in `vectors/keys/seeds.json`. Expected ids and JWT
bytes were constructed independently of the checker. No operational key is used.

| Named test | Required behavior and forbidden neighboring outcome |
| --- | --- |
| `test_media_type_token_boundaries` | Ordinary JSON and case-insensitive charset with HTTP whitespace accept; a space inside `application` refuses as `unsupported_media_type` without reservation. |
| `test_media_subtype_token_boundaries` | The same valid controls accept; a space inside `json` refuses as `unsupported_media_type` without reservation. |
| `test_signed_enrollment_structured_union` | A signed structured UID-map name with a leading-hyphen host accepts; putting that name in the legacy-only explicit list or exceeding the mxid byte cap refuses as `enrollment_malformed`, preserving prior authority. |
| `test_signed_registration_structured_union` | A signed structured request name with a leading-hyphen host accepts; exceeding the configured-audience mxid byte cap refuses as `name_invalid` without reservation. The registry UID map uses `legacy.dev` to isolate the request-name guard. |

The ordinary JSON fixture also supplies a positive control for the legacy UID-map
and explicit-list grammar. Long-audience neighbors use valid DNS labels; their
legacy explicit name fits the cap while their structured candidate exceeds it.
External trust, clock and sink results remain fixture inputs. These checks do
not qualify a service endpoint or deployment.
