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
set_result STATUS "summary" "evidence" applicable
```

Use `true` or `false` for `applicable`. Omission defaults to `true`.

### Choosing a result

- Use `GOOD` only when collected evidence proves compliance with the implemented criterion.
- Use `VULNERABLE` only when collected evidence proves a violation.
- Use `MANUAL` for business necessity, approved exceptions, organization policy, external identity state, current vendor-advisory review, or an otherwise reliable but incomplete decision.
- Use `NOT_APPLICABLE` only when absence or non-applicability was established.
- Use `ERROR` when required evidence cannot be read, trusted, or parsed reliably.

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
- automation mode gates publication on 67 final results with no `MANUAL` or `ERROR` status;
- policy review IDs change when the complete redacted technical basis changes;
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
