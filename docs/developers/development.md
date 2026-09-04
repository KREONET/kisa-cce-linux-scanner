# Development

## Repository layout

```text
bin/                    Public launcher.
data/                   Version and ordered criterion catalog.
docs/                   Operator, design, security, development, and packaging documentation.
lib/                    Private main file, shared helpers, resolvers, and check modules.
LICENSES/               LGPLv3, incorporated GPLv3, and BSD 3-Clause license texts.
man/                    Installed section 8 command manual source.
tests/                  Generated-fixture regression suite.
Makefile                Validation and installation interface.
```

The project has no generated source code and no production build dependency. Packaging copies the launcher, private shell files, runtime data, and section 8 manual into a staged filesystem. Repository Markdown is not installed by `make install`.

## Contribution licensing

Unless explicitly stated otherwise before submission, contributions intended
for inclusion in this project must be provided under
`LGPL-3.0-or-later OR BSD-3-Clause`. Contributors must have the right to submit
the work under both licenses. KISA CCE GUIDE material and other third-party
content remain subject to their original terms and are not relicensed by this
policy.

## Local validation

Run the required syntax and regression suite:

```bash
make check
```

Run ShellCheck separately:

```bash
make lint
```

`make check` runs the named regression groups in `tests/run.sh` and focused tests for evidence schemas, typed policy facts, report rendering, redaction, non-systemd procfs runtime collection, system-check failure precedence, numeric UID handling, sysctl, PAM, systemd, listeners, and dependency propagation. The suite creates all fixtures under a protected temporary directory and removes them at exit.

### Ubuntu 26.04 coreutils compatibility

Ubuntu 26.04 uses rust-coreutils 0.8.0 as its default core-utility provider,
while `cp`, `mv`, and `rm` remain GNU implementations. The Resolute GNU package
is based on coreutils 9.7. These are deliberate mixed-provider release
semantics, not a reason to branch scanner behavior on a command's implementation
name or `--version` text. See the official
[rust-coreutils update](https://discourse.ubuntu.com/t/an-update-on-rust-coreutils/80773),
[Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/),
and [Resolute GNU coreutils package](https://packages.ubuntu.com/resolute/gnu-coreutils).

`tests/uutils_compatibility.sh` runs only on Ubuntu 26.04 and executes the exact
capabilities required by the scanner: GNU-style `stat` fields, `readlink -f`,
NUL-delimited `sort -z`, the `date -r -u` timestamp form, `sha256sum --`, and
`install` directory and file modes. Other platforms report a skip. Extend this
test whenever production code adopts another option form. Do not replace it
with provider-name or version matching; compatible implementations are accepted
and incompatible behavior fails at the exercised capability boundary.

`tests/ntpd_rs.sh` independently verifies the optional ntpd-rs U-65 adapter:
strict `/etc/ntpd-rs/ntp.toml` source parsing, native configuration validation,
multi-source `ntp-ctl status` normalization, `ntpd-rs.service` persistence,
and provider-bound policy matching. The fixtures cover `nts-pool`, bracketed
IPv6, unknown-key rejection, and every observed peer. Keep Chrony as the
expected Ubuntu 26.04 provider in fixtures; ntpd-rs
is a selected operational extension. The Canonical timeline is documented in
the [ntpd-rs transition plan](https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154).

Performance measurements are separate from correctness gates because they need Linux `strace`, GNU `time`, and a baseline source tree. See [Scan performance architecture](../design/performance.md).

## Implementing or changing a criterion

### Catalog contract

`data/criteria.tsv` is ordered and must contain exactly one row for every U-01 through U-67 result. Runtime validation enforces this exact ordered range in addition to the four-column header, tab separators, and non-empty metadata fields:

```text
code	category	severity	title
```

Do not add an implementation-only diagnostic as a new KISA result. Expose supporting diagnostics through a separate command mode, as `--explain-sysctl` does.

### Function contract

Implement `U-NN` as `check_u_nn` in the module responsible for its category:

| Range | Module |
|---|---|
| U-01 through U-33 | `lib/kisa-cce-checks/_account-file.sh` |
| U-34 through U-63 | `lib/kisa-cce-checks/_service.sh` |
| U-64 through U-67 | `lib/kisa-cce-checks/_system.sh` |

Every executed function must call:

```bash
set_result STATUS "summary" "evidence" applicable \
  RESOLUTION_CLASS REMEDIATION_ELIGIBLE REMEDIATION_RULE_ID
```

Use `true` or `false` for `applicable`. Omission defaults to `true`. Resolution
class defaults to `technical`; remediation eligibility defaults to `false` and
the rule ID defaults to empty.

Resolution class is `technical`, `policy`, `runtime`, or `external`. Use
`policy` only when complete technical evidence exists and organization intent
is the remaining input. Use `runtime` when current host state is missing,
`external` for identity, vendor, or other authoritative data outside the host,
and `technical` for parser or configuration uncertainty.

Eligibility can be true only for `VULNERABLE` with a nonempty lowercase
versioned rule ID, such as `metadata.u37.v1`. Every other result must use false
and an empty rule ID. Invalid combinations are converted to `ERROR`.

### Choosing a result

- Use `GOOD` only when collected evidence proves compliance with the implemented criterion.
- Use `VULNERABLE` only when collected evidence proves a violation.
- Use `MANUAL` for business necessity, approved exceptions, organization policy, external identity state, current vendor-advisory review, or an otherwise reliable but incomplete decision.
- Use `NOT_APPLICABLE` only when absence or non-applicability was established.
- Use `ERROR` when required evidence cannot be read, trusted, or parsed reliably.

In complete and automation modes, technical, runtime, and external manual
results become `ERROR`; attestations can resolve only policy-class manual
results. Automation converts an absent policy attestation to non-actionable
`VULNERABLE` with `decision_basis=fail_closed_policy`. Do not mark that result
remediation-eligible.

Missing input is not automatically `GOOD` or `NOT_APPLICABLE`.

### Filesystem access

- Pass logical absolute paths through `fs_path`.
- Use rooted read helpers when following files or directories that may be symlinks.
- Treat an existing path that cannot be resolved safely as an error.
- Preserve target-root display paths in evidence rather than leaking staging paths.
- Do not write into `SCAN_ROOT`.
- Use NUL-delimited records for recursive pathname streams. Newline- or tab-delimited recursive inventories are not safe for general pathnames.
- Extend the shared full-filesystem collector when U-15, U-23, U-25, or U-33 needs another inode field; do not add another independent traversal.
- Treat cached filesystem facts as one immutable run-scoped snapshot. A direct test that mutates its fixture must reset the cache before the next check.

### Runtime commands

- Gate live-only collection with `runtime_enabled`.
- Resolve external tools through `trusted_command` or `capture_command`.
- Use native validators when their output fully represents the configuration being assessed.
- Check command exit status and distinguish unavailable, absent, and invalid states.
- Do not execute reload, restart, apply, update, or network-fetch operations.

### Configuration formats

Do not apply a generic last-match grep to a layered subsystem. Document and test all applicable behavior, including:

- directory precedence and equal-basename replacement;
- lexical order;
- main-file versus drop-in order;
- include recursion, cycles, and depth limits;
- masks and symlinks;
- first-obtained versus last-obtained directives;
- conditional sections;
- manager-normalized and runtime state.

Return `MANUAL` or `ERROR` when the implemented model cannot prove the native result.

### Evidence content

Evidence must be concise, reviewable, and free of raw secrets. Prefer counts, modes, ownership, selected directive values, source paths with line numbers, and explicit collection-state fields.

Do not emit password hashes, private keys, TSIG material, tokens, SNMP credentials, complete access-control files, or full command output. The shared redactor is defense in depth, not authorization to collect excessive data.

### Debug event contract

Use `debug_emit` for internal diagnostics. Do not use `set -x`, `BASH_XTRACEFD`, direct writes to file descriptor 2, or ad hoc debug files. The function accepts one event name followed by unique key and value pairs. Event and key identifiers must match `[a-z][a-z0-9_]*`; `schema`, `event`, and `truncated` are reserved envelope keys. Keep the schema stable and use enum-like values for state.

Pass only bounded operational metadata. Allowed examples include a criterion code, subsystem name, cache action, normalized collection status, count, and exit status. Do not pass command arguments, raw stdout or stderr, configuration lines, result summaries, evidence, policy data, review IDs, bundle digests, credentials, or report paths. Treat logical paths as sensitive and include one only when it is necessary to identify a failed source. The encoder percent-escapes bytes outside `[A-Za-z0-9._~:/@+-]`, limits each rendered `key=value` field to 256 bytes, and limits each event to 2048 bytes. These limits are a final boundary, not permission to submit arbitrary data.

Every new debug event requires a regression that verifies its exact schema and state transition. Also verify that debug-disabled execution emits no debug events, debug output stays on standard error with dmesg framing, hostile values cannot create fields or terminal lines, and debug mode does not alter reports or exit status.

## Implementing or changing a patch rule

Metadata patch rules belong in
`lib/kisa-cce-patcher/_metadata-rules.sh`; transaction and rollback primitives
belong in `lib/kisa-cce-patcher/_engine.sh`. Keep orchestration and scanner
subprocess handling for the public fixed path in
`lib/kisa-cce-cli/_patch-main.sh`. Full-profile domain ordering belongs in the
private `lib/kisa-cce-patcher/_orchestrator.sh`. Every private filename starts
with `_`, and functional directories retain the `kisa-cce-` prefix.

The coverage contract must remain exactly 67 unique rows. Its current state is
9 `fixed`, 58 `conditional`, and 0 `gated`. Fixed rules need no site value.
Conditional rules have implemented typed adapter boundaries, and every
mutating path has rollback, but they still require their registered input and evidence. Ordinary CLI operations
dispatch the nine fixed rules; `--automatic --desired-state FILE` dispatches
the complete contract through `_orchestrator.sh` and
`_orchestrator-domains.sh`.

Fixed U-12 and U-62 content belongs in
`lib/kisa-cce-patcher/_configuration-transaction.sh`. Its plan and manifest
must remain in the main checksum inventory, and its backups, payloads, and
journal must be restored with the metadata domain during rollback. Do not turn
that fixed registry into an arbitrary content input.

A fixed patch rule must use one criterion code, logical path, owner policy, and
maximum mode. A conditional rule may consume only the exact input type named in
`_coverage.sh`; the desired-state compiler supplies its risk, domain,
postcondition, validator, and rollback fields from that contract. Do not accept
arbitrary paths, shell commands, or untyped desired values from an operator,
policy file, report, or transaction. The scanner check remains the source of
truth for compliance; update its platform semantics and transaction validator
together when a threshold changes.

U-37 and U-67 are bounded multi-target exceptions to the single-path pattern.
Their enumerators must use fixed criterion-owned roots, no-follow NUL-delimited
inventories, one-filesystem boundaries, and one fingerprint and rollback row
per target. U-67 remains live-root-only because the patcher has no offline mount
evidence input.

Preserve these invariants:

- dry run is the default and mutation requires explicit `--apply`;
- every selected criterion has a conclusive fresh pre-scan result;
- all paths and metadata pass preflight before the first mutation;
- symbolic links, hard-linked regular files, and object types unsupported by
  the selected rule are never remediated; directory targets require an explicit
  bounded rule such as U-67;
- device, inode, UID, GID, and mode are compared again before change;
- size and mtime remain unchanged, regular-file content digests remain equal,
  and ctime is exact before the first metadata mutation;
- modes can only lose permission bits and a rule cannot broaden access;
- a complete protected rollback transaction exists before change;
- a new scanner invocation verifies every applied rule;
- apply or verification failure attempts reverse-order rollback;
- manual rollback refuses an unexpected root, inode, or metadata state;
- `--automatic` is root-only, requires a complete desired-state v2 profile,
  implies apply, selects U-01 through U-67, and reaches `verified` only through
  the complete post-scan and rollback gates.

Public fixed-rule result consumption must require the exact combination
`resolution_class=technical`, `remediation_eligible=true`, and the registered
versioned rule ID before planning a vulnerable result. A policy fail-closed
vulnerability is not a patch instruction.

Add focused tests for compliant, vulnerable, absent, symlink, hard-link,
non-regular, unreadable, concurrent-drift, partial-apply, failed post-scan,
automatic rollback, manual rollback, modified transaction, wrong-root
transaction, and already-restored cases. Run the public command in dry-run,
apply, and rollback modes from a staged installation. Complete the supported
distribution and version container matrix, and use a booted host when a future
rule depends on runtime behavior. See
[Autopatcher](../design/autopatcher.md).

For `--automatic`, test the root and `--desired-state` requirements, exact
67-row selection, rejection of `--checks` and `--rollback`, explicit output
path, protected default transaction creation, verified, failed, and
external-action status records, exit status 3, successful all-conforming
post-scan, and both rollback outcomes.

### System transaction adapters

U-64 through U-67 system adapter work belongs in
`lib/kisa-cce-patcher/_system-transaction.sh`. Keep package simulation,
time-provider configuration, logging configuration, and U-67 metadata
delegation as distinct cases.

- U-64 must verify signed repository and advisory evidence plus an immutable
  snapshot and rollback token before a package-manager simulation. It returns
  `external_action_required`; it never performs package mutation.
- U-65 requires a typed approved source, a provider-specific persistent
  configuration, an enable/start unit plan, native validation, and a fresh
  runtime probe. Supported providers are Chrony, NTPsec, systemd-timesyncd, and
  ntpd-rs.
- U-66 accepts only typed journald persistence or an rsyslog selector and
  destination. It requires native validation and fresh unit-state verification.
- U-67 delegates to `metadata.u67.v1` and must not duplicate the log metadata
  enumerator.

Every callback executable must be an absolute root-owned regular file with no
group or other write bit and a root-owned non-writable parent chain. Never place
raw credentials, snapshot tokens, or rollback tokens in plans or transaction
artifacts. Run `tests/system_transaction.sh` as root and non-root on Ubuntu
26.04, Debian 13, and Rocky Linux 10 when changing the automatic system domain.

U-65 and U-66 must remain recoverable after the originating Bash process exits.
`patch_system_load_transaction ROOT DIR` validates the protected manifest,
checksums, rule-derived path and payload, root identity, optional backup, state,
and applied record. `patch_system_rollback_transaction ROOT DIR strict` requires
the exact applied file fingerprint and unit state. Use `transition` only for a
bounded retry after interrupted recovery; it accepts configuration and unit
state only when each matches a recorded before or after state. Focused tests
must cover manifest tampering, target drift, an interrupted rollback that writes
`rollback_failed`, and a successful cross-process retry to `rolled_back`. U-64
must not enter this rollback API because it performs no package mutation.

### Conditional domains and all-domain orchestration

The 58 conditional rows are implemented by these private modules:

| Module | Criteria count | Focused test |
|---|---:|---|
| `_account-transaction.sh` | 10 | `tests/patch_account_transaction.sh` |
| `_pam-transaction.sh` | 3 | `tests/pam_transaction.sh` |
| `_inventory-transaction.sh` | 6 | `tests/patch_inventory_transaction.sh` |
| `_filesystem-transaction.sh` | 8 | `tests/patch_filesystem_transaction.sh` |
| `_service-transaction.sh` | 9 | `tests/patch_service_transaction.sh` |
| `_network-service-transaction.sh` | 11 | `tests/patch_network_service_transaction.sh` |
| `_edge-service-transaction.sh` | 8 | `tests/edge_service_transaction.sh` |
| `_system-transaction.sh` | 3 | `tests/system_transaction.sh` |

Keep provider parsers and serializers in their owning domain. A domain may
return `NOT_APPLICABLE` for a proven absent provider and must reject unresolved
include graphs, custom invocation, unsafe paths, stale evidence, and callback
drift. Account, service, firewall, package, credential, and runtime operations
must not be recast as generic file replacement.

External callback executables must be absolute root-owned regular files with
root-owned non-writable parent chains. Orchestrator domain callbacks are
registered functions from already loaded trusted modules. Store a secret
reference or digest when the adapter requires a credential; never place
plaintext secrets in plan, manifest, callback argument, or report data. An
operation outside the local transaction boundary uses
`external_action_required`, not a synthetic `verified` result.

`patch_desired_state_policy_compile` accepts restricted schema-version-2 YAML
and emits protected contract-derived TSV. Fixed rows use `none` and `-`;
conditional rows require their exact registered input type and a nonempty
value. Full automatic mode invokes this compiler internally. The separate
`kisa-cce-policy-compile` command remains the schema-version-1 scanner policy
compiler.

`patch_orchestrator_plan` requires exactly 67 unique compiled profile rows and
67 unique scanner results. Register plan, apply, verify, and rollback callbacks
for every actionable domain through `_orchestrator-domains.sh`. The orchestrator binds both input files, root
device/inode, request files, domain order, and plan digests. It applies domains
in order and rolls them back in reverse order.

Complex profile values must reference absolute root-owned mode-`0600` domain
input TSV files. Keep the record grammar criterion-specific, validate referenced
files separately, and reject symbolic links, repeated separators, explicit dot
or parent components, and untrusted callback executables. Never place a
plaintext secret in profile, domain input, plan, or callback arguments.

After domain verification, assert `awaiting_post_scan`. Only a fresh JSONL file
with every U-01 through U-67 status equal to `GOOD` or `NOT_APPLICABLE` may call
the final transition to `verified`. Test `VULNERABLE`, `MANUAL`, `ERROR`, reused,
duplicate, missing, and malformed post-scan rejection. Keep strict and
transition cross-process rollback coverage, including checksum tampering and a
partially applied domain. Run `tests/patch_orchestrator.sh` directly for focused
work, `tests/patch_full_automatic.sh` for the public integration, and both
through `make check`. Changes to `--automatic`, `--desired-state`, or domain
input records require CLI, usage, and man-page updates together.

## Adding a resolver

Place reusable precedence and path logic in `lib/kisa-cce-resolvers/_resolvers.sh`. Keep criterion-specific policy in the relevant check module. A resolver should return distinct statuses for:

1. value established;
2. value absent;
3. collection or interpretation failure.

Add fixtures for the normal path, override path, masked or excluded path, malformed input, and offline symlink escape where applicable.

## Regression expectations

Changes to collection or reporting should preserve these invariants:

- exactly one result for every selected catalog row;
- exactly 67 results for a full scan;
- no duplicate criterion code;
- JSONL has one final summary line;
- Markdown headings, summary rows, and JSONL result codes agree;
- report files remain mode `0600`;
- unsupported platforms fail unless explicitly allowed;
- shared filesystem checks retain their counts, evidence order, and error precedence when collected together or selected individually;
- offline absolute symlinks remain within the selected root;
- installed `/usr/lib` and optional libexec layouts both run from a `DESTDIR` tree;
- hostile `BASH_ENV` and `ENV` values are not loaded;
- debug mode preserves report content and exit status, emits only framed English diagnostics on standard error, and does not expose raw assessed content;
- complete mode records 67 final results with no `MANUAL` status;
- automation mode publishes only 67 tri-state results, closes an unattested
  policy result to non-actionable `VULNERABLE`, and blocks technical, runtime,
  external, or invalid-policy errors;
- every JSONL criterion record has a valid resolution class, boolean
  remediation eligibility, and rule ID relationship;
- policy review IDs use review schema 2 and change when resolution class or the
  complete redacted basis changes;
- evidence bundle identity, checksum, freshness, service, listener, and mount contracts remain enforced.

## Packaging smoke test

The regression suite exercises `make install`, but a manual staging check is useful when changing `Makefile`:

```bash
stage_directory="$(mktemp -d)"
make install DESTDIR="$stage_directory" prefix=/usr
"$stage_directory/usr/bin/kisa-cce-scan" --version
```

Do not embed `DESTDIR` into installed files. The staged launcher must resolve private modules and data relative to its staged prefix.

See [Packaging](../packaging/README.md) for the filesystem contract and pending metadata.

## Documentation maintenance

Update documentation in the same change when modifying:

| Change | Required document |
|---|---|
| CLI option, mode, output, or exit behavior | `docs/operators/usage.md` |
| Installed CLI syntax or operator behavior | `man/kisa-cce-scan.8` |
| Patcher rule, transaction, apply, or rollback behavior | `docs/design/autopatcher.md`, `docs/operators/usage.md`, and `man/kisa-cce-patch.8` |
| Policy authoring or compiler behavior | `docs/reference/policy-format.md` and `man/kisa-cce-policy-compile.8` |
| Component boundary or resolver semantics | `docs/design/architecture.md` |
| Trust assumption, privileged behavior, or sensitive evidence | `docs/design/security-model.md` |
| Install path or package build interface | `docs/packaging/README.md` |
| Supported platform or criterion scope | Root `README.md`, `docs/README.md`, and `docs/reference/platform-support.md` |
| Rendered-guide family branch or versioned native behavior | `docs/reference/kisa-platform-semantics.md` |

## Release gates

Before a release candidate:

1. Update `data/VERSION` once.
2. Run `make check` and `make lint`.
3. Build staged Debian and RPM package candidates from the same source tree.
4. Verify package ownership, modes, dependency metadata, upgrade, and removal behavior.
5. Run complete acceptance scans on every listed product and release.
6. Review reports for false `GOOD` results, missing evidence, and secret exposure.

The repository does not yet include final Debian/RPM metadata or completed target-platform acceptance evidence.
