# Local service adapters

These adapters implement specification §4.3–4.4, §7 and §9 where local mechanisms
are decided. The `cmd/registrar` binary wires them to the admission and HTTP
packages. Git and FileStore implement `registry.Verifier` and `registry.Store`;
the command bridges the neutral clock/audit values to the core types.

| Adapter | Entry points | Authority and failure boundary |
| --- | --- | --- |
| Git | `NewGit`, `Read`, `Verify`, `Descends` | Exact full commit, approved SSH signature, exact entry set and Git ancestry; no branch following, working-tree authority or fetch. |
| High-water | `NewFileStore`, `Load`, `Inspect`, `HighWaterDigest`, `Commit` | Full-state CAS under a stable exclusive lock, temporary file, file fsync, rename, directory fsync. Every error leaves durability indeterminate. |
| TLS | `LoadTLS` | One private local certificate/key pair; generic failures omit paths and underlying parser diagnostics. |
| Signer | `LoadSigner`, `PublicKey`, `Sign` | One PKCS8 PEM Ed25519 generation. Generic failures contain neither paths nor key bytes. |
| Clock | `NewClock`, `Startup`, `Now`, `Deadline` | System UTC/monotonic time; explicit evidence must attest synchronization and startup ordering. Faults latch for the instance. |
| Audit | `NewAudit`, `Append`, `Acknowledge`, `Probe`, `Head`, `Close` | Canonical exact-schema lines, LF-inclusive hash chain, local fsync and exclusive writer. Remote acknowledgement must match exact durable bytes. |
| Configuration | `LoadConfig`, `ParseConfig` | Strict CCJ-1 bytes and schema; LoadConfig checks root ownership of configuration/pins and service custody of the optional audit token. |

`Load` always returns `Reconciled: false`, even after a successful local write.
Missing/restored files cannot establish freshness. After any Commit error, fence
admission using neither the old nor new state. A restart still needs external
operator reconciliation, including explicit bootstrap authorization for an absent
file. `Commit(nil, next)` merely implements the CAS creation primitive. `Inspect`
returns local evidence or explicit absence; `HighWaterDigest` identifies its
canonical bytes. Neither grants freshness. The command obtains an operator
attestation from its controlling terminal for that starting process only and
then uses the real CAS. No reconciliation marker is written; see the root
README for `serve --reconcile`.

`NewProductionClock` consumes `github.com/relux-works/swarma-credential-broker/timeconf`
at `e7619dfc4b2a6cf1696d8a21eff603bc80f147c7` (the policy documents use the
same commit). Linux 5.11+ and proc access are required by its collector.
`CollectorEntry` is the first statement in command main. No local chrony parser
or second production profile exists. The provider preserves conservative
nanosecond rounding; the adapter requires trusted, fresh, unexpired evidence,
with nonnegative uncertainty at most 1.5 seconds and an excluded authority endpoint.

Startup performs a provider start check, a full four-second monotonic hold with
intermediate checks, then another start check before fixing UTC and the immutable
`floor(fixed UTC)+31` barrier. Wall progress cannot shorten the hold. A monitor
samples every 100 ms after each completed collection and admission also takes a
fresh sample. Unavailable, unhealthy, expired, over-cap or backward-step evidence
latches the process fence; health recovery never clears it. Any detected negative
wall/monotonic discontinuity fences, including a shared incident over one second.
Observation intervals cannot prove absence of an unobserved transient; smooth slew
and measurement jitter require deployment qualification under §7.

Admission maps faulted readings to typed `clock_skew`. The command stops serving,
joins handlers and detached audit, closes the sink, then exits 75 with
`registrar: clock fenced`. Failed drains retain shutdown failure and leave a live
sink open. The supervisor must exclude the old process before restart and bound
restart attempts. Test evidence remains injection only.

There is **no production Remote implementation or network sink**. Without one,
local recording works but Acknowledge returns `audit_unavailable`. A future
authenticated, append-only durable sink must acknowledge the SHA-256 of the
exact line including LF, support idempotent replay and honor cancellation.
Shipping sends retained prerequisites in sequence before the requested line;
restart replays from the beginning. Acknowledge checks the complete durable local
chain, file identity and permissions under local serialization before shipping,
after each successful remote call and before success, including deduplication.
It does not hold the local mutex across remote calls. Observed custody faults
latch until explicit exact-head recovery; restoring a pathname or mode alone
cannot reopen acknowledgement. These checks linearize local custody at validation;
they do not prevent an external writer from changing a file after the check.
Probe can recover only the exact cached head,
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
| `object_format` | Required protected repository profile: exactly `sha1` or `sha256`. No default or inference from revision length. Passed unchanged to the loader, Git, store/digest and audit constructors. |
| `revision` | Exactly 40 lowercase hex characters for `sha1`, or 64 for `sha256`, as selected by protected `object_format`. Not a branch, tag, abbreviated or cross-format ID. |
| `allowed_signers` | Absolute clean path to protected OpenSSH allowed-signers material for approved registry maintainers. |
| `time_policy` | Absolute clean protected registrar policy path, e.g. `/etc/timeconf/policy.json`. Required by `serve` except `--loopback-test-http`; if present, always validated. Root-owned regular file, no group/other write, no final symlink. Only option A; raised platform bounds refuse startup. |
| `publisher_key` | Strict canonical enrollment-publisher public-key string accepted by enrollment.NewPolicy. The containing configuration protects this pin. |
| `stations` | Object mapping valid host labels to booleans, for example `{"host-a":false}`. |
| `high_water`, `signing_key`, `audit_file` | Absolute clean file paths without NUL or expansion. Use separate files/directories for state, audit and signing material. |
| `audit_homeserver` | Optional string; all four audit strings or none. HTTPS origin only: ASCII §5 server name, optional port 1–65535, no path (even `/`), query, userinfo, fragment, escapes, whitespace or backslash. Spelling is preserved. |
| `audit_room` | Full `!opaque:server` room ID, never an alias; nonempty components and valid server byte-equal to `audit_user`'s server. |
| `audit_user` | Full `@localpart:server`, split at the first colon after `@`. Localpart uses §5 structured or legacy grammar and configured-audience 255-byte mxid bound; server is byte-equal to `audience`, including case, port and trailing dot. No normalization. |
| `audit_token` | Absolute clean token-file path. Service-owned regular 0600 file in a service-owned 0700 immediate directory, opened with O_NOFOLLOW and checked on its descriptor, like `signing_key`. Content is 1–4096 visible ASCII bytes (0x21–0x7e), no whitespace or trimming. |
| `audit_retired_localparts` | Separate array of exact §5 localparts under the same audience length bound; no duplicates, full mxids or current audit localpart. Required with the profile enabled and retained permanently once any account is retired. Alone never enables the profile. With no retirement history and profile off, absent or empty is valid. |
| `per_key`, `per_name` | Optional integer limits, respectively 1–10 and 1–3. Defaults 10 and 3. |
| `listen` | Optional literal IP:port, default `127.0.0.1:8443`. |
| `tls_certificate`, `tls_key` | Optional paired absolute clean paths; serve requires them except in explicit loopback HTTP test mode. Both require service-owned 0600 files in service-owned 0700 immediate directories. |
| `first_use` | Optional exact full configured revision, never a boolean. Only explicit operator-confirmed bootstrap may use absent state. |

All audit configuration and token violations return `configuration_invalid`
before any network call. Row 19b refuses exact current audit identity components
and all retired localparts even when enrollment permits them. It runs after
name/audience validation, both limiter debits and nonce reservation; earlier
refusals keep precedence and accounting is never refunded.

The four strings currently enable startup validation and name exclusion only.
No Matrix Remote is implemented: otherwise issuable requests still refuse with
`audit_unavailable`, including with the profile enabled. Network delivery,
read-back, room policy, reconciliation and replay remain unimplemented.
Operators must preserve the append-only retired list through replacement,
disablement and restore. With the profile off, a missing list cannot reveal
prior retirement history from configuration bytes alone (§11.2).

Configuration, time-policy and allowed-signers files must be root-owned, regular and have no
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
  disable replace refs, grafts, shallow boundaries, commit-graph reads, hooks,
  fsmonitor, lazy fetch, prompts and global/system configuration. Grafts and
  shallow metadata use fixed `/dev/null` inputs; `core.commitGraph=false` wins
  over repository configuration. Protocols default to refused; a local explicit
  protocol allowance cannot trigger lazy fetch because it is disabled separately.
  Subprocess diagnostics are discarded. Alternate stores may supply objects,
  but cannot replace signature approval. Tests cover wrong-signer alternates,
  repository trust/program overrides and a local promisor trap. This is a bounded
  metadata/configuration sweep, not a general filesystem-compromise proof.
  See Git's [graph behavior](https://git-scm.com/docs/commit-graph),
  [graph format](https://git-scm.com/docs/gitformat-commit-graph) and
  [repository layout](https://git-scm.com/docs/gitrepository-layout).
- Five-second Git Read/Descends and audit startup deadlines. Per-command output
  limits include 4 MiB for Git tree listings; registry count/aggregate/file limits
  remain those in §4.4. Audit lines are additionally bounded to 16 KiB.
- Configuration and allowed-signers input limits are 64 KiB; PKCS8 input 16 KiB;
  audit token 4096 bytes;
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

## Shared option-A policy runbook

This registrar loads the path named by `time_policy` in its protected config,
for example `/etc/timeconf/policy.json`, through its own `loadTimePolicy` and
`readProtectedWith` root-custody loader. It requires a root-owned regular file,
a non-root service UID, no group/other write bits, and no final symlink. The
install mode below is 0644. It then calls `DecodePolicy` and `Production`;
it does not call the provider's private-file `LoadPolicy`. Exact contents
(durations are integer nanoseconds):

```json
{
  "source": "chrony-nts-config",
  "chronyc": "/usr/bin/chronyc",
  "source_files": ["/etc/chrony/chrony.conf"],
  "max_sync_age_ns": 2048000000000,
  "max_uncertainty_ns": 1500000000,
  "max_offset_ns": 500000000,
  "max_root_distance_ns": 1000000000,
  "authority_window_ns": 300000000000,
  "backward_tolerance_ns": 1000000000,
  "step_tolerance_ns": 60000000000,
  "timeout_ns": 1000000000,
  "max_output_bytes": 4096,
  "resync": "new-authenticated-sync"
}
```

After preparing `policy.json`, install as root into the root-owned, non-writable
`/etc/timeconf` directory:

```sh
install -o root -g root -m 0644 policy.json /etc/timeconf/policy.json
```

Other consumers use their own policy and custody rules; this is
not a shared-file installation contract. Keymaker nests `time_policy` in its own
`config.json`. At provider pin
[`e7619df`](https://github.com/relux-works/swarma-credential-broker/tree/e7619dfc4b2a6cf1696d8a21eff603bc80f147c7),
`LoadPolicy` uses service-UID ownership and exact mode 0600
([`timeconf/collect_linux.go:99-136`](https://github.com/relux-works/swarma-credential-broker/blob/e7619dfc4b2a6cf1696d8a21eff603bc80f147c7/timeconf/collect_linux.go#L99-L136)).
The example uses `backward_tolerance_ns: 1000000000` (1 second), the provider's
ceiling at broker `e7619df`
([`timeconf/policy.go:30`](https://github.com/relux-works/swarma-credential-broker/blob/e7619dfc4b2a6cf1696d8a21eff603bc80f147c7/timeconf/policy.go#L30),
[`timeconf/policy.go:63`](https://github.com/relux-works/swarma-credential-broker/blob/e7619dfc4b2a6cf1696d8a21eff603bc80f147c7/timeconf/policy.go#L63)).
Below 1 second, the provider's sampling jitter (BOOTTIME then REALTIME reads) is
refused as a backward step and the service never becomes available; this was
measured on a real host.
The registrar refuses a lower value as `configuration_invalid` at configuration
load, before any provider start; the provider's `Validate` rejects values above
the ceiling. The registrar also independently fences detected backward interval
discontinuities.

The closed configuration inventory must match the running chronyd configuration,
including included files. A minimal protected `/etc/chrony/chrony.conf` source
example is:

```conf
server time-a.example.org iburst nts maxpoll 10
server time-b.example.org iburst nts maxpoll 10
```

Replace example names with qualified NTS sources. Keep the source files and
executable protected against untrusted writes. Option A infers NTS from this
configuration and selected-source matching; it does not prove authenticated
per-source operation. This runbook is a template, not installation evidence.

Narrow validation for this adapter slice (Go 1.26.10, Linux):

```sh
GOTOOLCHAIN=local go test ./internal/adapters/... ./cmd/registrar/...
GOTOOLCHAIN=local go vet ./internal/adapters/... ./cmd/registrar/...
GOTOOLCHAIN=local go mod tidy -diff
```

Outputs and fixture scratch belong under `.temp/`. These commands supplement
the broader repository checks; full and race review runs are separate.
