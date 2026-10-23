# Local service adapters

These adapters implement specification §4.3–4.4, §7 and §9 where local mechanisms
are decided. They do not provide a service binary. Admission and HTTP wiring is
deferred until those packages land. Git and FileStore implement the landed
`registry.Verifier` and `registry.Store`; clock/audit values are neutral named
types for that later wiring to translate. No unlanded package is imported.

| Adapter | Entry points | Authority and failure boundary |
| --- | --- | --- |
| Git | `NewGit`, `Read`, `Verify`, `Descends` | Exact full commit, approved SSH signature, exact entry set and Git ancestry; no branch following, working-tree authority or fetch. |
| High-water | `NewFileStore`, `Load`, `Commit` | Full-state CAS under a stable exclusive lock, temporary file, file fsync, rename, directory fsync. Every error leaves durability indeterminate. |
| Signer | `LoadSigner`, `PublicKey`, `Sign` | One PKCS8 PEM Ed25519 generation. Generic failures contain neither paths nor key bytes. |
| Clock | `NewClock`, `Startup`, `Now`, `Deadline` | System UTC/monotonic time; explicit evidence must attest synchronization and startup ordering. Faults latch for the instance. |
| Audit | `NewAudit`, `Append`, `Acknowledge`, `Probe`, `Head`, `Close` | Canonical exact-schema lines, LF-inclusive hash chain, local fsync and exclusive writer. Remote acknowledgement must match exact durable bytes. |
| Configuration | `LoadConfig`, `ParseConfig` | Strict CCJ-1 bytes and schema; only LoadConfig checks root ownership of configuration and allowed-signers material. |

`Load` always returns `Reconciled: false`, even after a successful local write.
Missing/restored files cannot establish freshness. After any Commit error, fence
admission using neither the old nor new state. A restart still needs external
operator reconciliation, including explicit bootstrap authorization for an absent
file. `Commit(nil, next)` merely implements the CAS creation primitive.

There is **no production ClockEvidence implementation**. Capture actual process
entry time with `time.Now()` and preserve its monotonic component when constructing
Clock. Evidence must be trusted and nonblocking, attest ordering against every
old admission and latch transient loss/backward steps between observations.
Absent evidence reports unhealthy and faulted; waiting never clears that fence.
The in-memory evidence implementation exists only in tests. Admission must map
unhealthy/faulted readings to `clock_skew` and enforce its startup barrier.

There is **no production Remote implementation or network sink**. Without one,
local recording works but Acknowledge returns `audit_unavailable`. A future
authenticated, append-only durable sink must acknowledge the SHA-256 of the
exact line including LF, support idempotent replay and honor cancellation.
Shipping sends retained prerequisites in sequence before the requested line;
restart replays from the beginning. Probe can recover only the exact cached head,
never truncate, repair, adopt a different tip or establish off-host durability.
An ambiguous append may require operator reconciliation and a new instance.
Close requires quiesced callers and waits for an outstanding remote call.

## Startup configuration

One root-owned regular JSON file is read once. Unknown/missing fields, duplicate
members, invalid CCJ-1, coercions and invalid values are rejected. ParseConfig is
for bytes only and must not substitute for LoadConfig at startup.

| Field | Required type and rule |
| --- | --- |
| `v` | Integer 1. |
| `audience` | 1–255 ASCII bytes satisfying the [Matrix server-name grammar](https://spec.matrix.org/v1.17/appendices/#server-name), such as `example.org` or `[2001:db8::1]:8448`. No normalization, URL or DNS lookup. |
| `repository` | Absolute clean local repository path, such as `/srv/registrar/registry`. |
| `revision` | Full lowercase 40- or 64-hex commit ID. Not a branch, tag or abbreviated ID. |
| `allowed_signers` | Absolute clean path to protected OpenSSH allowed-signers material for approved registry maintainers. |
| `publisher_key` | Strict canonical enrollment-publisher public-key string accepted by enrollment.NewPolicy. The containing configuration protects this pin. |
| `stations` | Object mapping valid host labels to booleans, for example `{"host-a":false}`. |
| `high_water`, `signing_key`, `audit_file` | Absolute clean file paths without NUL or expansion. Use separate files/directories for state, audit and signing material. |
| `per_key`, `per_name` | Optional integer limits, respectively 1–10 and 1–3. Defaults 10 and 3. |

Configuration and allowed-signers files must be root-owned, regular and have no
group/other write permission; running as root is refused. Final symlinks are
refused. The operator must protect their directory namespace and maintain it
throughout service lifetime: checking a file at startup does not secure writable
ancestors or defend against privileged replacement. Git uses the configured
allowed-signers path for signature verification, so pin rotation requires a
controlled restart rather than uncoordinated file replacement.

Signing, high-water, audit and lock files require the service UID and exactly
0600, with a service-owned 0700 immediate directory. Unsafe modes are refused,
never silently repaired. The signing key is one unencrypted `PRIVATE KEY` PEM
block containing PKCS8 Ed25519. No machine/user keyring or environment credential
is read. Errors expose only static codes. Registry diagnostics may carry a
restricted logical enrollment path, never a local filesystem path.

## Choices and operational limits

The specification does not fix these adapter details:

- Linux/POSIX no-follow opens and advisory `flock`; exactly 0600/0700 local
  permissions; nonblocking lock contention fails closed rather than waits.
  Cooperating writers retain the stable lock file and do not unlink it.
- SSH signatures only, using system Git and ssh-keygen resolved at startup.
  The launcher must supply a trusted executable search path. Fixed Git overrides
  disable replace refs, hooks, fsmonitor, protocols, lazy fetch, prompts and
  global/system configuration; subprocess diagnostics are discarded.
- Five-second Git Read/Descends and audit startup deadlines. Per-command output
  limits include 4 MiB for Git tree listings; registry count/aggregate/file limits
  remain those in §4.4. Audit lines are additionally bounded to 16 KiB.
- Configuration and allowed-signers input limits are 64 KiB; PKCS8 input 16 KiB;
  retained high-water input 64 MiB. These conservative adapter limits refuse
  excess input rather than truncate or normalize it.
- Version-1 high-water encoding is canonical CCJ-1 with `v` and `high_water`;
  nested field names are the exported registry HighWater/HostWater field names.
  Unknown, missing, mis-cased and noncanonical retained data is refused.
- Invalid startup configuration returns startup-only `configuration_invalid`;
  Git/storage failures return `registry_unavailable` (oversized individual blobs
  return `enrollment_malformed`). Non-descendant ancestry returns false, allowing
  the loader to issue `registry_rollback`. Signer failures are
  `service_unavailable`; audit failures are `audit_unavailable`. Clock conveys
  health/fence evidence for admission's `clock_skew`, not an HTTP response.
- Local syscall I/O is synchronous. Context is checked around operations and
  during scanning/shipping, but a blocked kernel fsync/write is not forcibly
  interrupted. A production integration must qualify finite I/O deadlines for
  its storage/runtime; this adapter does not prove that deployment property.

## Validation

From the repository root, run `GOMAXPROCS=2 go test ./internal/...` and
`GOMAXPROCS=2 go vet ./...`. Git and OpenSSH ssh-keygen must be installed. Set
`TMPDIR` to a scratch directory to contain disposable fixture repositories,
generated SSH test keys and Go scratch output; no network is used. The tests
sign fixture commits with keys generated in those tests, and use published fixed
test seeds for file-signing fixtures. No fixture uses machine signing keys.

Tests pair rejections with positive controls and check post-failure state.
Persistence injection before each named operation proves error propagation and
visible old/new bytes, not power-loss durability. Root-owned acceptance uses
synthetic UID metadata because the test account cannot create root-owned files;
actual ownership/mode rejection and filesystem operations are separate real
checks. No test establishes production clock trust, off-host durability,
privileged configuration acceptance, bounded blocked-kernel I/O or deployment
readiness. A subsequent service integration must qualify those properties.
