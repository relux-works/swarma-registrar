# Registry extension seam

There is no plugin loader, plugin manifest or global registration function in this module. The public extension seam is `registry.Verifier` and `registry.Store`, passed to `registry.Loader`. These are Go interface aliases exported by [registry.go](../../../../registry/registry.go); their contracts are implemented in [internal/registry/registry.go](../../../../internal/registry/registry.go), `Verifier`, `Store`, `Loader.Load`, and forwarded by [internal/library/registry.go](../../../../internal/library/registry.go), `Loader`/`Load`.

## Write and wire an adapter

Implement these exact methods using the public types:

```text
// registry.Verifier
Verify(revision string, entries []registry.Entry) error
Descends(candidate, previous string) (bool, error)

// registry.Store
Commit(previous *registry.HighWater, next registry.HighWater) error
```

These are interface method signatures, not free functions or an additional API. `Verify` must bind the complete selected enrollment entries, including path, kind and exact bytes, to the exact protected approved signed commit. It must not fetch or follow a branch. `Descends` supplies ancestry evidence; false becomes rollback, unavailable evidence fails closed. The loader skips that check when the approved revision is unchanged.

`Commit` compares the complete previous state against durable current state, atomically replaces it, and returns success only after durability. Use `HighWater.Clone()` to copy nested retained state. A returned error makes durability indeterminate: `Load` returns neither snapshot nor replacement high-water. Fence admission, including use of old snapshots, and treat retained state as unreconciled until freshness is established again. The interface itself provides no file persistence or cross-process locking.

Wire instances through the actual fields `registry.Loader.ObjectFormat`, `Policy`, `Verifier` and `Store`; then call `Load` with `registry.Input.Revision`, `Entries`, `Retained`, `FirstUse` and `Reconciled`. This dependency injection is the entire registration step. `ObjectFormat` is a protected `sha1`/`sha256` choice. `Policy` comes from `enrollment.NewPolicy`. `FirstUse` is an explicit bootstrap decision with no retained state; reloads need retained evidence and an independent freshness attestation through `Reconciled`. Do not derive these booleans from whether a local file exists.

The loader filters immediate `enrollments/*.json` entries, sorts them by path and validates every selected file through each phase before advancing: envelope/CCJ/size, reserved authority, body schema, ID, publisher signature, ownership conflicts, then rollback/history. Only after all phases can `Store.Commit` publish authority. Preserve the complete enrollment entry set at the source boundary; filtering is not permission for a verifier to ignore omitted enrollment files.

Existing service adapters are internal, not public plugin packages. [Git](../../../../internal/adapters/git.go), `NewGit`, `Git.Read`, `Git.Verify`, `Git.Descends`, and [FileStore](../../../../internal/adapters/store.go), `NewFileStore`, `FileStore.Inspect`, `FileStore.Commit`, show the local implementation. Command [openProduction](../../../../cmd/registrar/main.go) constructs them, and [reconcile](../../../../cmd/registrar/reconcile.go) wires them through a confirmation-gated store. A consumer outside this module supplies its own public-interface implementations; changing executable adapters requires changing its Go wiring, not adding a plugin flag.

## Test the supplied implementation

Use the existing [public fixture](../../../../registry/example_test.go), `fixtureVerifier`, `fixtureStore`, `ExampleLoader_Load`, as the minimal wiring pattern. Its verifier accepts only one fixed revision and exact entry set; its store checks prior state and clones replacement data. Its in-memory store demonstrates CAS only and has no crash durability. The example's successful current record is `host-a` sequence 2; its historical key is absent, its current key is found, and `Authorize("host-a", "legacy.dev")` refuses `name_not_permitted`.

For a new consumer adapter, pair a valid exact-revision/entry-set load with altered-byte, omitted-entry and unapproved-revision refusals. For reloads, verify descendant acceptance, non-descendant refusal and ancestry-error refusal. Exercise stale-prior CAS rejection and persistence errors; failed loads return no new authority. Validation failures before commit must not call the store. Keep post-failure admission fenced even if old snapshot methods still return data. Qualify real storage durability separately from an in-memory control.

Existing cases to inspect when building these tests:

| Case | Source and symbol |
| --- | --- |
| Protected object format accepts its own revision width and refuses missing/other profiles | [registry/revision_test.go](../../../../registry/revision_test.go), `TestLoaderObjectFormat` |
| Exact/current-only key lookup, copying accessors, revoked/expired data and failed reload | [registry/query_test.go](../../../../registry/query_test.go), `TestCurrentKeyLookupAndCopies` |
| Missing policy refuses alongside a valid control | [registry/query_test.go](../../../../registry/query_test.go), `TestMissingPolicyAndValidControl` |
| Snapshot-wide refusal order and no partial persistence | [internal/registry/registry_test.go](../../../../internal/registry/registry_test.go), `TestSnapshotPhaseOrder` |
| History removal, ancestry rollback and failed replacement state | [internal/registry/registry_test.go](../../../../internal/registry/registry_test.go), `TestRollbackAndAtomicity` |

These fixture cases specify observable contracts; they do not establish a new adapter's trust, crash durability or deployment readiness. Public API inventories in [registry/api.txt](../../../../registry/api.txt) guard exported names only.
